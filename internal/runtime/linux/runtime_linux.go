//go:build linux

package linux

import (
 "bytes"
 "context"
 "encoding/base64"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strings"

 "github.com/Tony855/S5M-Agent-WireGuard/internal/config"
 "github.com/Tony855/S5M-Agent-WireGuard/internal/secret"
 wr "github.com/Tony855/S5M-Agent-WireGuard/internal/runtime"
)

type Runner interface {
 LookPath(string) (string,error)
 Run(context.Context,string,...string) ([]byte,error)
}
type execRunner struct{}
func (execRunner) LookPath(s string)(string,error){ return exec.LookPath(s) }
func (execRunner) Run(ctx context.Context, name string,args ...string)([]byte,error){
 c:=exec.CommandContext(ctx,name,args...); var stderr bytes.Buffer; c.Stderr=&stderr
 out,err:=c.Output(); if err!=nil{return nil,fmt.Errorf("%s failed: %w: %s",name,err,strings.TrimSpace(stderr.String()))}; return out,nil
}
type Runtime struct { DataDir string; Runner Runner }
func New(dataDir string)*Runtime{return &Runtime{DataDir:dataDir,Runner:execRunner{}}}
func(r *Runtime) runner()Runner{if r.Runner!=nil{return r.Runner};return execRunner{}}
func(r *Runtime) Probe(context.Context)wr.Capabilities{
 c:=wr.Capabilities{Backend:"linux-kernel",SupportsClient:true,SupportsServer:true}
 if _,e:=r.runner().LookPath("ip");e!=nil{c.Reason="iproute2 ip binary is unavailable";return c}
 if _,e:=r.runner().LookPath("wg");e!=nil{c.Reason="wireguard-tools wg binary is unavailable";return c}
 c.Available=true;c.Features=[]string{"kernel-wireguard","ipv4","ipv6","peer-handshake-status","transfer-counters"};return c
}
func(r *Runtime) Apply(ctx context.Context,cfg config.Config)error{
 if cfg.Interface.Backend!="linux-kernel"{return errors.New("Linux runtime only accepts linux-kernel backend")}
 if e:=cfg.Validate(r.DataDir);e!=nil{return fmt.Errorf("validate config: %w",e)}
 if !r.Probe(ctx).Available{return errors.New("Linux WireGuard runtime prerequisites are unavailable")}
 for _,p:=range cfg.Peers{for _,cidr:=range p.AllowedIPs{if cidr=="0.0.0.0/0"||cidr=="::/0"{return errors.New("default-route AllowedIPs are blocked until explicit route policy is implemented")}}}
 run:=r.runner()
 if _,e:=run.Run(ctx,"ip","link","show","dev",cfg.Interface.Name);e==nil{return errors.New("interface already exists; refusing non-transactional in-place update; stop before applying a replacement")}
 if _,e:=run.Run(ctx,"ip","link","add","dev",cfg.Interface.Name,"type","wireguard");e!=nil{return fmt.Errorf("create WireGuard interface: %w",e)}
 committed:=false
 defer func(){if !committed{_,_=run.Run(context.Background(),"ip","link","delete","dev",cfg.Interface.Name)}}()
 conf,cleanup,e:=r.buildWGConfig(cfg);if e!=nil{return e};defer cleanup()
 if _,e=run.Run(ctx,"wg","setconf",cfg.Interface.Name,conf);e!=nil{return fmt.Errorf("apply WireGuard configuration: %w",e)}
 if cfg.Interface.MTU>0{if _,e=run.Run(ctx,"ip","link","set","dev",cfg.Interface.Name,"mtu",fmt.Sprint(cfg.Interface.MTU));e!=nil{return fmt.Errorf("set MTU: %w",e)}}
 for _,a:=range cfg.Interface.Addresses{if _,e=run.Run(ctx,"ip","address","replace",a,"dev",cfg.Interface.Name);e!=nil{return fmt.Errorf("assign interface address: %w",e)}}
 if _,e=run.Run(ctx,"ip","link","set","dev",cfg.Interface.Name,"up");e!=nil{return fmt.Errorf("bring interface up: %w",e)}
 committed=true;return nil
}
func(r *Runtime) buildWGConfig(cfg config.Config)(string,func(),error){
 key,e:=secret.ReadKey(r.DataDir,cfg.Interface.PrivateKeyFile);if e!=nil{return "",func(){},fmt.Errorf("read private key: %w",e)};defer wipe(key)
 var b strings.Builder
 b.WriteString("private_key = ");b.WriteString(base64.StdEncoding.EncodeToString(key));b.WriteByte('\n')
 if cfg.Interface.ListenPort>0{fmt.Fprintf(&b,"listen_port = %d\n",cfg.Interface.ListenPort)}
 for _,p:=range cfg.Peers{
  b.WriteString("\n[Peer]\npublic_key = ");b.WriteString(p.PublicKey);b.WriteByte('\n')
  if p.Endpoint!=""{b.WriteString("endpoint = ");b.WriteString(p.Endpoint);b.WriteByte('\n')}
  b.WriteString("allowed_ips = ");b.WriteString(strings.Join(p.AllowedIPs,", "));b.WriteByte('\n')
  if p.PersistentKeepalive>0{fmt.Fprintf(&b,"persistent_keepalive_interval = %d\n",p.PersistentKeepalive)}
  if p.PresharedKeyFile!=""{psk,err:=secret.ReadKey(r.DataDir,p.PresharedKeyFile);if err!=nil{return "",func(){},fmt.Errorf("read peer preshared key: %w",err)};b.WriteString("preshared_key = ");b.WriteString(base64.StdEncoding.EncodeToString(psk));b.WriteByte('\n');wipe(psk)}
 }
 dir:=filepath.Join(r.DataDir,"runtime");if e=os.MkdirAll(dir,0700);e!=nil{return "",func(){},fmt.Errorf("create runtime directory: %w",e)}
 f,e:=os.CreateTemp(dir,"wg-setconf-*.conf");if e!=nil{return "",func(){},fmt.Errorf("create temporary config: %w",e)}
 path:=f.Name();cleanup:=func(){_=os.Remove(path)}
 if e=f.Chmod(0600);e!=nil{_=f.Close();cleanup();return "",func(){},e}
 if _,e=f.WriteString(b.String());e!=nil{_=f.Close();cleanup();return "",func(){},e}
 if e=f.Sync();e!=nil{_=f.Close();cleanup();return "",func(){},e}
 if e=f.Close();e!=nil{cleanup();return "",func(){},e}
 return path,cleanup,nil
}
func(r *Runtime) Status(ctx context.Context,name string)(wr.Status,error){
 if !validName(name){return wr.Status{},errors.New("invalid interface name")}
 s:=wr.Status{Interface:name,Backend:"linux-kernel"}
 if _,e:=r.runner().Run(ctx,"ip","link","show","dev",name);e!=nil{return s,nil}
 s.Running=true;if _,e:=r.runner().Run(ctx,"wg","show",name);e!=nil{s.LastError="interface exists but WireGuard status could not be read"};return s,nil
}
func(r *Runtime) Stop(ctx context.Context,name string)error{
 if !validName(name){return errors.New("invalid interface name")}
 if _,e:=r.runner().Run(ctx,"ip","link","delete","dev",name);e!=nil{return fmt.Errorf("delete WireGuard interface: %w",e)};return nil
}
func validName(n string)bool{if len(n)==0||len(n)>15{return false};for _,c:=range n{if !(c=='-'||c=='_'||c=='.'||c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'){return false}};return true}
func wipe(b []byte){for i:=range b{b[i]=0}}
