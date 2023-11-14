package propose

import (
	pb "github.com/xuperchain/yogurt-chain/ychain/protos"
)

type ProposeManager interface {
	GetProposalByID(proposalID string) (*pb.Proposal, error)
}
