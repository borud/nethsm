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

// checks if the DistinguishedName type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &DistinguishedName{}

// DistinguishedName struct for DistinguishedName
type DistinguishedName struct {
	CountryName *string `json:"countryName,omitempty"`
	StateOrProvinceName *string `json:"stateOrProvinceName,omitempty"`
	LocalityName *string `json:"localityName,omitempty"`
	OrganizationName *string `json:"organizationName,omitempty"`
	OrganizationalUnitName *string `json:"organizationalUnitName,omitempty"`
	CommonName string `json:"commonName"`
	EmailAddress *string `json:"emailAddress,omitempty"`
}

type _DistinguishedName DistinguishedName

// NewDistinguishedName instantiates a new DistinguishedName object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDistinguishedName(commonName string) *DistinguishedName {
	this := DistinguishedName{}
	this.CommonName = commonName
	return &this
}

// NewDistinguishedNameWithDefaults instantiates a new DistinguishedName object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDistinguishedNameWithDefaults() *DistinguishedName {
	this := DistinguishedName{}
	return &this
}

// GetCountryName returns the CountryName field value if set, zero value otherwise.
func (o *DistinguishedName) GetCountryName() string {
	if o == nil || IsNil(o.CountryName) {
		var ret string
		return ret
	}
	return *o.CountryName
}

// GetCountryNameOk returns a tuple with the CountryName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DistinguishedName) GetCountryNameOk() (*string, bool) {
	if o == nil || IsNil(o.CountryName) {
		return nil, false
	}
	return o.CountryName, true
}

// HasCountryName returns a boolean if a field has been set.
func (o *DistinguishedName) HasCountryName() bool {
	if o != nil && !IsNil(o.CountryName) {
		return true
	}

	return false
}

// SetCountryName gets a reference to the given string and assigns it to the CountryName field.
func (o *DistinguishedName) SetCountryName(v string) {
	o.CountryName = &v
}

// GetStateOrProvinceName returns the StateOrProvinceName field value if set, zero value otherwise.
func (o *DistinguishedName) GetStateOrProvinceName() string {
	if o == nil || IsNil(o.StateOrProvinceName) {
		var ret string
		return ret
	}
	return *o.StateOrProvinceName
}

// GetStateOrProvinceNameOk returns a tuple with the StateOrProvinceName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DistinguishedName) GetStateOrProvinceNameOk() (*string, bool) {
	if o == nil || IsNil(o.StateOrProvinceName) {
		return nil, false
	}
	return o.StateOrProvinceName, true
}

// HasStateOrProvinceName returns a boolean if a field has been set.
func (o *DistinguishedName) HasStateOrProvinceName() bool {
	if o != nil && !IsNil(o.StateOrProvinceName) {
		return true
	}

	return false
}

// SetStateOrProvinceName gets a reference to the given string and assigns it to the StateOrProvinceName field.
func (o *DistinguishedName) SetStateOrProvinceName(v string) {
	o.StateOrProvinceName = &v
}

// GetLocalityName returns the LocalityName field value if set, zero value otherwise.
func (o *DistinguishedName) GetLocalityName() string {
	if o == nil || IsNil(o.LocalityName) {
		var ret string
		return ret
	}
	return *o.LocalityName
}

// GetLocalityNameOk returns a tuple with the LocalityName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DistinguishedName) GetLocalityNameOk() (*string, bool) {
	if o == nil || IsNil(o.LocalityName) {
		return nil, false
	}
	return o.LocalityName, true
}

// HasLocalityName returns a boolean if a field has been set.
func (o *DistinguishedName) HasLocalityName() bool {
	if o != nil && !IsNil(o.LocalityName) {
		return true
	}

	return false
}

// SetLocalityName gets a reference to the given string and assigns it to the LocalityName field.
func (o *DistinguishedName) SetLocalityName(v string) {
	o.LocalityName = &v
}

// GetOrganizationName returns the OrganizationName field value if set, zero value otherwise.
func (o *DistinguishedName) GetOrganizationName() string {
	if o == nil || IsNil(o.OrganizationName) {
		var ret string
		return ret
	}
	return *o.OrganizationName
}

// GetOrganizationNameOk returns a tuple with the OrganizationName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DistinguishedName) GetOrganizationNameOk() (*string, bool) {
	if o == nil || IsNil(o.OrganizationName) {
		return nil, false
	}
	return o.OrganizationName, true
}

// HasOrganizationName returns a boolean if a field has been set.
func (o *DistinguishedName) HasOrganizationName() bool {
	if o != nil && !IsNil(o.OrganizationName) {
		return true
	}

	return false
}

// SetOrganizationName gets a reference to the given string and assigns it to the OrganizationName field.
func (o *DistinguishedName) SetOrganizationName(v string) {
	o.OrganizationName = &v
}

// GetOrganizationalUnitName returns the OrganizationalUnitName field value if set, zero value otherwise.
func (o *DistinguishedName) GetOrganizationalUnitName() string {
	if o == nil || IsNil(o.OrganizationalUnitName) {
		var ret string
		return ret
	}
	return *o.OrganizationalUnitName
}

// GetOrganizationalUnitNameOk returns a tuple with the OrganizationalUnitName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DistinguishedName) GetOrganizationalUnitNameOk() (*string, bool) {
	if o == nil || IsNil(o.OrganizationalUnitName) {
		return nil, false
	}
	return o.OrganizationalUnitName, true
}

// HasOrganizationalUnitName returns a boolean if a field has been set.
func (o *DistinguishedName) HasOrganizationalUnitName() bool {
	if o != nil && !IsNil(o.OrganizationalUnitName) {
		return true
	}

	return false
}

// SetOrganizationalUnitName gets a reference to the given string and assigns it to the OrganizationalUnitName field.
func (o *DistinguishedName) SetOrganizationalUnitName(v string) {
	o.OrganizationalUnitName = &v
}

// GetCommonName returns the CommonName field value
func (o *DistinguishedName) GetCommonName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CommonName
}

// GetCommonNameOk returns a tuple with the CommonName field value
// and a boolean to check if the value has been set.
func (o *DistinguishedName) GetCommonNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CommonName, true
}

// SetCommonName sets field value
func (o *DistinguishedName) SetCommonName(v string) {
	o.CommonName = v
}

// GetEmailAddress returns the EmailAddress field value if set, zero value otherwise.
func (o *DistinguishedName) GetEmailAddress() string {
	if o == nil || IsNil(o.EmailAddress) {
		var ret string
		return ret
	}
	return *o.EmailAddress
}

// GetEmailAddressOk returns a tuple with the EmailAddress field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DistinguishedName) GetEmailAddressOk() (*string, bool) {
	if o == nil || IsNil(o.EmailAddress) {
		return nil, false
	}
	return o.EmailAddress, true
}

// HasEmailAddress returns a boolean if a field has been set.
func (o *DistinguishedName) HasEmailAddress() bool {
	if o != nil && !IsNil(o.EmailAddress) {
		return true
	}

	return false
}

// SetEmailAddress gets a reference to the given string and assigns it to the EmailAddress field.
func (o *DistinguishedName) SetEmailAddress(v string) {
	o.EmailAddress = &v
}

func (o DistinguishedName) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o DistinguishedName) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.CountryName) {
		toSerialize["countryName"] = o.CountryName
	}
	if !IsNil(o.StateOrProvinceName) {
		toSerialize["stateOrProvinceName"] = o.StateOrProvinceName
	}
	if !IsNil(o.LocalityName) {
		toSerialize["localityName"] = o.LocalityName
	}
	if !IsNil(o.OrganizationName) {
		toSerialize["organizationName"] = o.OrganizationName
	}
	if !IsNil(o.OrganizationalUnitName) {
		toSerialize["organizationalUnitName"] = o.OrganizationalUnitName
	}
	toSerialize["commonName"] = o.CommonName
	if !IsNil(o.EmailAddress) {
		toSerialize["emailAddress"] = o.EmailAddress
	}
	return toSerialize, nil
}

func (o *DistinguishedName) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"commonName",
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

	varDistinguishedName := _DistinguishedName{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varDistinguishedName)

	if err != nil {
		return err
	}

	*o = DistinguishedName(varDistinguishedName)

	return err
}

type NullableDistinguishedName struct {
	value *DistinguishedName
	isSet bool
}

func (v NullableDistinguishedName) Get() *DistinguishedName {
	return v.value
}

func (v *NullableDistinguishedName) Set(val *DistinguishedName) {
	v.value = val
	v.isSet = true
}

func (v NullableDistinguishedName) IsSet() bool {
	return v.isSet
}

func (v *NullableDistinguishedName) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDistinguishedName(val *DistinguishedName) *NullableDistinguishedName {
	return &NullableDistinguishedName{value: val, isSet: true}
}

func (v NullableDistinguishedName) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDistinguishedName) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


