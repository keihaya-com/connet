package connet

import "github.com/keihaya-com/connet/pb"

type Binding struct {
	Realm string
	Name  string
}

func NewBindingPB(b *pb.Binding) Binding {
	return Binding{
		Realm: b.Realm,
		Name:  b.Name,
	}
}

func (b Binding) AsPB() *pb.Binding {
	return &pb.Binding{
		Realm: b.Realm,
		Name:  b.Name,
	}
}

func NewBindingsPB(pbs []*pb.Binding) []Binding {
	s := make([]Binding, len(pbs))
	for i, pb := range pbs {
		s[i] = NewBindingPB(pb)
	}
	return s
}
