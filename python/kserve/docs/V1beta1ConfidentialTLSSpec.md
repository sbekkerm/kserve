# V1beta1ConfidentialTLSSpec

ConfidentialTLSSpec identifies KBS resources for the serving TLS material.
## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ca_resource_id** | **str** | CAResourceId is the KBS resource identifier for ca.crt, in the format kbs:///&lt;repo&gt;/&lt;type&gt;/&lt;tag&gt;. | [optional] 
**cert_resource_id** | **str** | CertResourceId is the KBS resource identifier for tls.crt, in the format kbs:///&lt;repo&gt;/&lt;type&gt;/&lt;tag&gt;. | [optional] 
**key_resource_id** | **str** | KeyResourceId is the KBS resource identifier for tls.key, in the format kbs:///&lt;repo&gt;/&lt;type&gt;/&lt;tag&gt;. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


