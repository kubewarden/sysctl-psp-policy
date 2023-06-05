// Code generated by go-swagger; DO NOT EDIT.

package v1

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

// GRPCAction GRPC action
//
// swagger:model GRPCAction
type GRPCAction struct {

	// Port number of the gRPC service. Number must be in the range 1 to 65535.
	// Required: true
	Port *int32 `json:"port"`

	// Service is the name of the service to place in the gRPC HealthCheckRequest (see https://github.com/grpc/grpc/blob/master/doc/health-checking.md).
	//
	// If this is not specified, the default behavior is defined by gRPC.
	Service string `json:"service,omitempty"`
}