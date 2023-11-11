# EUDI Wallet Reference Implementation

:heavy_exclamation_mark: **Important!** Before you proceed, please read the [EUDI Wallet Reference Implementation project description](wiki/EUDI_Wallet_Reference_Implementation.md)

----

# EUDI ISO 18013-5 iOS Wallet Kit library
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/actions/workflows/swift.yml/badge.svg)](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/actions/workflows/swift.yml)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=ncloc&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=duplicated_lines_density&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=reliability_rating&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit&metric=vulnerabilities&token=ceca670d1f503fb68c5545e9d6bf44465a5883a6)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-wallet-kit)

The initial implementation provides Proximity and Remote Flows for the EUDI Wallet. It is based on the following specifications:
- ISO/IEC 18013-5 – Published
- Presentation Exchange v2.0.0 - Published
- OpenID4VP – Draft 18
- SIOPv2 – Draft

## Initialization
The [EudiWallet](Documentation/Reference/classes/EudiWallet.md) class provides a unified API for the 2 user attestation presentation flows. It is initialized with a document storage manager instance. For SwiftUI apps, the wallet instance can be added as an ``environmentObject`` to be accessible from all views. A KeyChain implementation of document storage is available.

```swift
let wallet = EudiWallet.standard
wallet.userAuthenticationRequired = true
wallet.trustedReaderCertificates = [Data(name: "scytales_root_ca", ext: "der")!]
```	

## Storage Service
The read-only property ``storageService`` is an instance of a [DataStorageService](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-storage/blob/main/Documentation/Reference/protocols/DataStorageService.md) 
Currently the keychain implementation is used. It provides document management functionality using the iOS KeyChain.

## Presentation Service
The [presentation service protocol](Documentation/Reference/protocols/PresentationService.md) abstracts the presentation flow. The [BlePresentationService](Documentation/Reference/classes/BlePresentationService.md) and [OpenId4VpService](Documentation/Reference/classes/OpenId4VpService.md) classes implement the proximity and remote presentation flows respectively. The [PresentationSession](Documentation/Reference/classes/PresentationSession.md) class is used to wrap the presentation service and provide @Published properties for SwiftUI screens. The following example code demonstrates the initialization of a SwiftUI view with a new presentation session of a selected [flow type](Documentation/Reference/enums/FlowType.md).

```swift
let session = eudiWallet.beginPresentation(flow: flow)
// pass the session to a SwiftUI view
ShareView(presentationSession: session)
```

On view appearance the attestations are presented with the receiveRequest method. For the BLE (proximity) case the deviceEngagement property is populated with the QR code to be displayed on the holder device.

```swift
 .task {
	if isProximitySharing { try? await presentationSession.startQrEngagement() }
	 try? await presentationSession.receiveRequest()
  }

```
After the request is received the disclosedDocuments contains the requested attested items. It can be modified from the UI before the presentation is sent with user selective disclosure. Finally the presentation is sent with the following code: 

```swift
// Send the disclosed document items after biometric authentication (FaceID or TouchID)
// if the user cancels biometric authentication, onCancel method is called
_ = try await presentationSession.sendResponse(userAccepted: true,
  itemsToSend: presentationSession.disclosedDocuments.items, onCancel: { dismiss() })
```
### Dependencies

The detailed functionality of the wallet kit is implemented in the following Swift Packages: [MdocDataModel18013](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model.git), [MdocSecurity18013](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security.git),  [MdocDataTransfer18013](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-transfer.git) and
  [SiopOpenID4VP](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift.git)

### Sample application  
A sample application that demonstrates the usage of this library is [App Wallet UI](https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui).

### Disclaimer
The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.