/*
NetHSM

All endpoints expect exactly the specified JSON. Additional properties will cause a Bad Request Error (400). All HTTP errors contain a JSON structure with an explanation of type string. All [base64](https://tools.ietf.org/html/rfc4648#section-4) encoded values are Big Endian. 

API version: v1
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package api

import (
	"encoding/json"
	"bytes"
	"fmt"
)

// checks if the PublicKey type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &PublicKey{}

// PublicKey struct for PublicKey
type PublicKey struct {
	Mechanisms []KeyMechanism `json:"mechanisms"`
	Type KeyType `json:"type"`
	Restrictions KeyRestrictions `json:"restrictions"`
	Public *KeyPublicData `json:"public,omitempty"`
	Operations int32 `json:"operations"`
}

type _PublicKey PublicKey

// NewPublicKey instantiates a new PublicKey object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPublicKey(mechanisms []KeyMechanism, type_ KeyType, restrictions KeyRestrictions, operations int32) *PublicKey {
	this := PublicKey{}
	this.Mechanisms = mechanisms
	this.Type = type_
	this.Restrictions = restrictions
	this.Operations = operations
	return &this
}

// NewPublicKeyWithDefaults instantiates a new PublicKey object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPublicKeyWithDefaults() *PublicKey {
	this := PublicKey{}
	return &this
}

// GetMechanisms returns the Mechanisms field value
func (o *PublicKey) GetMechanisms() []KeyMechanism {
	if o == nil {
		var ret []KeyMechanism
		return ret
	}

	return o.Mechanisms
}

// GetMechanismsOk returns a tuple with the Mechanisms field value
// and a boolean to check if the value has been set.
func (o *PublicKey) GetMechanismsOk() ([]KeyMechanism, bool) {
	if o == nil {
		return nil, false
	}
	return o.Mechanisms, true
}

// SetMechanisms sets field value
func (o *PublicKey) SetMechanisms(v []KeyMechanism) {
	o.Mechanisms = v
}

// GetType returns the Type field value
func (o *PublicKey) GetType() KeyType {
	if o == nil {
		var ret KeyType
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *PublicKey) GetTypeOk() (*KeyType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *PublicKey) SetType(v KeyType) {
	o.Type = v
}

// GetRestrictions returns the Restrictions field value
func (o *PublicKey) GetRestrictions() KeyRestrictions {
	if o == nil {
		var ret KeyRestrictions
		return ret
	}

	return o.Restrictions
}

// GetRestrictionsOk returns a tuple with the Restrictions field value
// and a boolean to check if the value has been set.
func (o *PublicKey) GetRestrictionsOk() (*KeyRestrictions, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Restrictions, true
}

// SetRestrictions sets field value
func (o *PublicKey) SetRestrictions(v KeyRestrictions) {
	o.Restrictions = v
}

// GetPublic returns the Public field value if set, zero value otherwise.
func (o *PublicKey) GetPublic() KeyPublicData {
	if o == nil || IsNil(o.Public) {
		var ret KeyPublicData
		return ret
	}
	return *o.Public
}

// GetPublicOk returns a tuple with the Public field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PublicKey) GetPublicOk() (*KeyPublicData, bool) {
	if o == nil || IsNil(o.Public) {
		return nil, false
	}
	return o.Public, true
}

// HasPublic returns a boolean if a field has been set.
func (o *PublicKey) HasPublic() bool {
	if o != nil && !IsNil(o.Public) {
		return true
	}

	return false
}

// SetPublic gets a reference to the given KeyPublicData and assigns it to the Public field.
func (o *PublicKey) SetPublic(v KeyPublicData) {
	o.Public = &v
}

// GetOperations returns the Operations field value
func (o *PublicKey) GetOperations() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.Operations
}

// GetOperationsOk returns a tuple with the Operations field value
// and a boolean to check if the value has been set.
func (o *PublicKey) GetOperationsOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Operations, true
}

// SetOperations sets field value
func (o *PublicKey) SetOperations(v int32) {
	o.Operations = v
}

func (o PublicKey) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o PublicKey) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["mechanisms"] = o.Mechanisms
	toSerialize["type"] = o.Type
	toSerialize["restrictions"] = o.Restrictions
	if !IsNil(o.Public) {
		toSerialize["public"] = o.Public
	}
	toSerialize["operations"] = o.Operations
	return toSerialize, nil
}

func (o *PublicKey) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"mechanisms",
		"type",
		"restrictions",
		"operations",
	}

	allProperties := make(map[string]interface{})

	err = json.Unmarshal(data, &allProperties)

	if err != nil {
		return err;
	}

	for _, requiredProperty := range(requiredProperties) {
		if _, exists := allProperties[requiredProperty]; !exists {
			return fmt.Errorf("no value given for required property %v", requiredProperty)
		}
	}

	varPublicKey := _PublicKey{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varPublicKey)

	if err != nil {
		return err
	}

	*o = PublicKey(varPublicKey)

	return err
}

type NullablePublicKey struct {
	value *PublicKey
	isSet bool
}

func (v NullablePublicKey) Get() *PublicKey {
	return v.value
}

func (v *NullablePublicKey) Set(val *PublicKey) {
	v.value = val
	v.isSet = true
}

func (v NullablePublicKey) IsSet() bool {
	return v.isSet
}

func (v *NullablePublicKey) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePublicKey(val *PublicKey) *NullablePublicKey {
	return &NullablePublicKey{value: val, isSet: true}
}

func (v NullablePublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePublicKey) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


