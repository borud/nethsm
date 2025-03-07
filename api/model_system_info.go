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

// checks if the SystemInfo type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SystemInfo{}

// SystemInfo struct for SystemInfo
type SystemInfo struct {
	SoftwareVersion string `json:"softwareVersion"`
	SoftwareBuild string `json:"softwareBuild"`
	FirmwareVersion string `json:"firmwareVersion"`
	HardwareVersion string `json:"hardwareVersion"`
	DeviceId string `json:"deviceId"`
	AkPub AkPub `json:"akPub"`
	Pcr Pcr `json:"pcr"`
}

type _SystemInfo SystemInfo

// NewSystemInfo instantiates a new SystemInfo object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSystemInfo(softwareVersion string, softwareBuild string, firmwareVersion string, hardwareVersion string, deviceId string, akPub AkPub, pcr Pcr) *SystemInfo {
	this := SystemInfo{}
	this.SoftwareVersion = softwareVersion
	this.SoftwareBuild = softwareBuild
	this.FirmwareVersion = firmwareVersion
	this.HardwareVersion = hardwareVersion
	this.DeviceId = deviceId
	this.AkPub = akPub
	this.Pcr = pcr
	return &this
}

// NewSystemInfoWithDefaults instantiates a new SystemInfo object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSystemInfoWithDefaults() *SystemInfo {
	this := SystemInfo{}
	return &this
}

// GetSoftwareVersion returns the SoftwareVersion field value
func (o *SystemInfo) GetSoftwareVersion() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.SoftwareVersion
}

// GetSoftwareVersionOk returns a tuple with the SoftwareVersion field value
// and a boolean to check if the value has been set.
func (o *SystemInfo) GetSoftwareVersionOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SoftwareVersion, true
}

// SetSoftwareVersion sets field value
func (o *SystemInfo) SetSoftwareVersion(v string) {
	o.SoftwareVersion = v
}

// GetSoftwareBuild returns the SoftwareBuild field value
func (o *SystemInfo) GetSoftwareBuild() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.SoftwareBuild
}

// GetSoftwareBuildOk returns a tuple with the SoftwareBuild field value
// and a boolean to check if the value has been set.
func (o *SystemInfo) GetSoftwareBuildOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.SoftwareBuild, true
}

// SetSoftwareBuild sets field value
func (o *SystemInfo) SetSoftwareBuild(v string) {
	o.SoftwareBuild = v
}

// GetFirmwareVersion returns the FirmwareVersion field value
func (o *SystemInfo) GetFirmwareVersion() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FirmwareVersion
}

// GetFirmwareVersionOk returns a tuple with the FirmwareVersion field value
// and a boolean to check if the value has been set.
func (o *SystemInfo) GetFirmwareVersionOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FirmwareVersion, true
}

// SetFirmwareVersion sets field value
func (o *SystemInfo) SetFirmwareVersion(v string) {
	o.FirmwareVersion = v
}

// GetHardwareVersion returns the HardwareVersion field value
func (o *SystemInfo) GetHardwareVersion() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.HardwareVersion
}

// GetHardwareVersionOk returns a tuple with the HardwareVersion field value
// and a boolean to check if the value has been set.
func (o *SystemInfo) GetHardwareVersionOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.HardwareVersion, true
}

// SetHardwareVersion sets field value
func (o *SystemInfo) SetHardwareVersion(v string) {
	o.HardwareVersion = v
}

// GetDeviceId returns the DeviceId field value
func (o *SystemInfo) GetDeviceId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.DeviceId
}

// GetDeviceIdOk returns a tuple with the DeviceId field value
// and a boolean to check if the value has been set.
func (o *SystemInfo) GetDeviceIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.DeviceId, true
}

// SetDeviceId sets field value
func (o *SystemInfo) SetDeviceId(v string) {
	o.DeviceId = v
}

// GetAkPub returns the AkPub field value
func (o *SystemInfo) GetAkPub() AkPub {
	if o == nil {
		var ret AkPub
		return ret
	}

	return o.AkPub
}

// GetAkPubOk returns a tuple with the AkPub field value
// and a boolean to check if the value has been set.
func (o *SystemInfo) GetAkPubOk() (*AkPub, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AkPub, true
}

// SetAkPub sets field value
func (o *SystemInfo) SetAkPub(v AkPub) {
	o.AkPub = v
}

// GetPcr returns the Pcr field value
func (o *SystemInfo) GetPcr() Pcr {
	if o == nil {
		var ret Pcr
		return ret
	}

	return o.Pcr
}

// GetPcrOk returns a tuple with the Pcr field value
// and a boolean to check if the value has been set.
func (o *SystemInfo) GetPcrOk() (*Pcr, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Pcr, true
}

// SetPcr sets field value
func (o *SystemInfo) SetPcr(v Pcr) {
	o.Pcr = v
}

func (o SystemInfo) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SystemInfo) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["softwareVersion"] = o.SoftwareVersion
	toSerialize["softwareBuild"] = o.SoftwareBuild
	toSerialize["firmwareVersion"] = o.FirmwareVersion
	toSerialize["hardwareVersion"] = o.HardwareVersion
	toSerialize["deviceId"] = o.DeviceId
	toSerialize["akPub"] = o.AkPub
	toSerialize["pcr"] = o.Pcr
	return toSerialize, nil
}

func (o *SystemInfo) UnmarshalJSON(data []byte) (err error) {
	// This validates that all required properties are included in the JSON object
	// by unmarshalling the object into a generic map with string keys and checking
	// that every required field exists as a key in the generic map.
	requiredProperties := []string{
		"softwareVersion",
		"softwareBuild",
		"firmwareVersion",
		"hardwareVersion",
		"deviceId",
		"akPub",
		"pcr",
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

	varSystemInfo := _SystemInfo{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varSystemInfo)

	if err != nil {
		return err
	}

	*o = SystemInfo(varSystemInfo)

	return err
}

type NullableSystemInfo struct {
	value *SystemInfo
	isSet bool
}

func (v NullableSystemInfo) Get() *SystemInfo {
	return v.value
}

func (v *NullableSystemInfo) Set(val *SystemInfo) {
	v.value = val
	v.isSet = true
}

func (v NullableSystemInfo) IsSet() bool {
	return v.isSet
}

func (v *NullableSystemInfo) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSystemInfo(val *SystemInfo) *NullableSystemInfo {
	return &NullableSystemInfo{value: val, isSet: true}
}

func (v NullableSystemInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSystemInfo) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


