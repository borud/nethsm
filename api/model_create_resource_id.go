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

// checks if the CreateResourceId type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CreateResourceId{}

// CreateResourceId struct for CreateResourceId
type CreateResourceId struct {
	Id string `json:"id"`
}

type _CreateResourceId CreateResourceId

// NewCreateResourceId instantiates a new CreateResourceId object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCreateResourceId(id string) *CreateResourceId {
	this := CreateResourceId{}
	this.Id = id
	return &this
}

// NewCreateResourceIdWithDefaults instantiates a new CreateResourceId object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCreateResourceIdWithDefaults() *CreateResourceId {
	this := CreateResourceId{}
	return &this
}

// GetId returns the Id field value
func (o *CreateResourceId) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *CreateResourceId) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *CreateResourceId) SetId(v string) {
	o.Id = v
}

func (o CreateResourceId) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CreateResourceId) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["id"] = o.Id
	return toSerialize, nil
}

func (o *CreateResourceId) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"id",
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

	varCreateResourceId := _CreateResourceId{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varCreateResourceId)

	if err != nil {
		return err
	}

	*o = CreateResourceId(varCreateResourceId)

	return err
}

type NullableCreateResourceId struct {
	value *CreateResourceId
	isSet bool
}

func (v NullableCreateResourceId) Get() *CreateResourceId {
	return v.value
}

func (v *NullableCreateResourceId) Set(val *CreateResourceId) {
	v.value = val
	v.isSet = true
}

func (v NullableCreateResourceId) IsSet() bool {
	return v.isSet
}

func (v *NullableCreateResourceId) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCreateResourceId(val *CreateResourceId) *NullableCreateResourceId {
	return &NullableCreateResourceId{value: val, isSet: true}
}

func (v NullableCreateResourceId) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCreateResourceId) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


