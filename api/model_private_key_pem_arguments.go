/*
NetHSM

All endpoints expect exactly the specified JSON. Additional properties will cause a Bad Request Error (400). All HTTP errors contain a JSON structure with an explanation of type string. All [base64](https://tools.ietf.org/html/rfc4648#section-4) encoded values are Big Endian. 

API version: v1
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package api

import (
	"encoding/json"
)

// checks if the PrivateKeyPemArguments type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &PrivateKeyPemArguments{}

// PrivateKeyPemArguments struct for PrivateKeyPemArguments
type PrivateKeyPemArguments struct {
	Mechanisms []KeyMechanism `json:"mechanisms,omitempty"`
	Restrictions *KeyRestrictions `json:"restrictions,omitempty"`
}

// NewPrivateKeyPemArguments instantiates a new PrivateKeyPemArguments object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPrivateKeyPemArguments() *PrivateKeyPemArguments {
	this := PrivateKeyPemArguments{}
	return &this
}

// NewPrivateKeyPemArgumentsWithDefaults instantiates a new PrivateKeyPemArguments object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPrivateKeyPemArgumentsWithDefaults() *PrivateKeyPemArguments {
	this := PrivateKeyPemArguments{}
	return &this
}

// GetMechanisms returns the Mechanisms field value if set, zero value otherwise.
func (o *PrivateKeyPemArguments) GetMechanisms() []KeyMechanism {
	if o == nil || IsNil(o.Mechanisms) {
		var ret []KeyMechanism
		return ret
	}
	return o.Mechanisms
}

// GetMechanismsOk returns a tuple with the Mechanisms field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PrivateKeyPemArguments) GetMechanismsOk() ([]KeyMechanism, bool) {
	if o == nil || IsNil(o.Mechanisms) {
		return nil, false
	}
	return o.Mechanisms, true
}

// HasMechanisms returns a boolean if a field has been set.
func (o *PrivateKeyPemArguments) HasMechanisms() bool {
	if o != nil && !IsNil(o.Mechanisms) {
		return true
	}

	return false
}

// SetMechanisms gets a reference to the given []KeyMechanism and assigns it to the Mechanisms field.
func (o *PrivateKeyPemArguments) SetMechanisms(v []KeyMechanism) {
	o.Mechanisms = v
}

// GetRestrictions returns the Restrictions field value if set, zero value otherwise.
func (o *PrivateKeyPemArguments) GetRestrictions() KeyRestrictions {
	if o == nil || IsNil(o.Restrictions) {
		var ret KeyRestrictions
		return ret
	}
	return *o.Restrictions
}

// GetRestrictionsOk returns a tuple with the Restrictions field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PrivateKeyPemArguments) GetRestrictionsOk() (*KeyRestrictions, bool) {
	if o == nil || IsNil(o.Restrictions) {
		return nil, false
	}
	return o.Restrictions, true
}

// HasRestrictions returns a boolean if a field has been set.
func (o *PrivateKeyPemArguments) HasRestrictions() bool {
	if o != nil && !IsNil(o.Restrictions) {
		return true
	}

	return false
}

// SetRestrictions gets a reference to the given KeyRestrictions and assigns it to the Restrictions field.
func (o *PrivateKeyPemArguments) SetRestrictions(v KeyRestrictions) {
	o.Restrictions = &v
}

func (o PrivateKeyPemArguments) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o PrivateKeyPemArguments) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Mechanisms) {
		toSerialize["mechanisms"] = o.Mechanisms
	}
	if !IsNil(o.Restrictions) {
		toSerialize["restrictions"] = o.Restrictions
	}
	return toSerialize, nil
}

type NullablePrivateKeyPemArguments struct {
	value *PrivateKeyPemArguments
	isSet bool
}

func (v NullablePrivateKeyPemArguments) Get() *PrivateKeyPemArguments {
	return v.value
}

func (v *NullablePrivateKeyPemArguments) Set(val *PrivateKeyPemArguments) {
	v.value = val
	v.isSet = true
}

func (v NullablePrivateKeyPemArguments) IsSet() bool {
	return v.isSet
}

func (v *NullablePrivateKeyPemArguments) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePrivateKeyPemArguments(val *PrivateKeyPemArguments) *NullablePrivateKeyPemArguments {
	return &NullablePrivateKeyPemArguments{value: val, isSet: true}
}

func (v NullablePrivateKeyPemArguments) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePrivateKeyPemArguments) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


