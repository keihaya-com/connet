package pbc

import (
	"io"

	"github.com/keihaya-com/connet/pb"
)

func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{}
	if err := pb.Read(r, req); err != nil {
		return nil, err
	}
	return req, nil
}

func ReadResponse(r io.Reader) (*Response, error) {
	resp := &Response{}
	if err := pb.Read(r, resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp, nil
}