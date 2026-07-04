package main
import ("encoding/json";"fmt";"os";"strings"
 "github.com/T0ut4t1s/portolan/pkg/graph";"github.com/T0ut4t1s/portolan/pkg/snapshot")
func main(){
 data,_:=os.ReadFile(os.Args[1]); var s snapshot.Snapshot; json.Unmarshal(data,&s)
 g:=graph.Build(&s); deny:=map[string]bool{}
 for _,n:=range g.Namespaces{deny[n.Name]=n.DefaultDeny}
 nn:=func(id string)string{ if !strings.Contains(id,"/"){return ""}; return strings.SplitN(id,"/",2)[0]}
 n:=0
 for _,e:=range g.Edges{
  d:=nn(e.Dst)
  if d!="" && nn(e.Src)!="" && e.DeclaredEgress && !e.BroadEgress && !e.DeclaredIngress && deny[d] {
   n++; if n<=12 {fmt.Printf("  %s -> %s %v via %v\n",e.Src,e.Dst,e.Ports,e.Policies)}
  }
 }
 fmt.Println("egress-declared / ingress-missing into default-deny:",n)
}
