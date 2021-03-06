// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// PrefilterSpec CIDR ranges implemented in the Prefilter
// swagger:model PrefilterSpec

type PrefilterSpec struct {

	// deny
	Deny []string `json:"deny"`

	// revision
	Revision int64 `json:"revision,omitempty"`
}

/* polymorph PrefilterSpec deny false */

/* polymorph PrefilterSpec revision false */

// Validate validates this prefilter spec
func (m *PrefilterSpec) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDeny(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PrefilterSpec) validateDeny(formats strfmt.Registry) error {

	if swag.IsZero(m.Deny) { // not required
		return nil
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PrefilterSpec) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PrefilterSpec) UnmarshalBinary(b []byte) error {
	var res PrefilterSpec
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
