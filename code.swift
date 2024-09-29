extension AuthenticationViewController:ASAuthorizationProviderExtensionRegistrationHandler {
    func beginDeviceRegistration(loginManager: ASAuthorizationProviderExtensionLoginManager, options: ASAuthorizationProviderExtensionRequestOptions = [], completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void) {
        
        NSLog("[TDS PSSO] Begin Device Registration")
        NSLog("[TDS PSSO] Options: \(options)")
        // loginConfiguration
        NSLog("[TDS PSSO] loginConfiguration: \(loginManager.loginConfiguration)")
        let loginConfig =  ASAuthorizationProviderExtensionLoginConfiguration(clientID: "net.thomasdye.net.TDS.Apple.Mac.Login", issuer: "TDS", tokenEndpointURL: URL(string: "https://auth.thomasdye.net:1443/token")!, jwksEndpointURL:URL(string: "https://auth.thomasdye.net:1443/token")!, audience: "psso")
        
        loginConfig.tokenEndpointURL = URL(string: "https://auth.thomasdye.net:1443/token")!
        loginConfig.jwksEndpointURL = URL(string: "https://auth.thomasdye.net:1443/.well-known/jwks.json")!
//        loginConfig.keyEndpointURL = URL(string: "https://auth.thomasdye.net:1443/register")!
        loginConfig.nonceEndpointURL = URL(string: "https://auth.thomasdye.net:1443/nonce")!
        loginConfig.accountDisplayName = "TDS"
        
        NSLog("[TDS PSSO] clientID: \(loginConfig.clientID)")
        NSLog("[TDS PSSO] issuer: \(loginConfig.issuer)")
        NSLog("[TDS PSSO] audience: \(loginConfig.audience)")
        loginConfig.audience = "psso"
//        loginConfig.additionalScopes = "TDSMacLogin"
        
    
        
        
        
        
        if let token = PlatformAuthClass.Auth_Token.getToken() {
     
            DeviceRegisterRequest(loginConfig: loginConfig, loginManger: loginManager, token: token, completion: completion)
        } else {
            loginManager.presentRegistrationViewController(completion: {erros in
                if let error = erros {
                    NSLog(" [TDS PSSO] error 2 \(error)")
                    completion(.failed)
                }
                self.PlatformAuthClass.Request_Auth(viewController: self, comp: { login in
                    self.dismiss(self)
                    if login?.Finished  == true {
                        if let token = login?.info.JWTinfo?.JWT {
                            
                            self.DeviceRegisterRequest(loginConfig: loginConfig, loginManger: loginManager, token: self.PlatformAuthClass.Auth_Token.getToken()!, completion: completion)
                        }
                    }
                    
                })
                
            })
        }
        
        

    }
    

    
//    func beginUserRegistration(loginManager: ASAuthorizationProviderExtensionLoginManager, userName: String?, method authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod, options: ASAuthorizationProviderExtensionRequestOptions = [], completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void) {
//        NSLog("[TDS PSSO] Begin User Registration")
//        NSLog("[TDS PSSO] Options: \(options)")
//       
//        
//        
//        
//        
//        
//        if let token = PlatformAuthClass.Auth_Token.getToken()  {
//            
//            
//            let Request = TDSUserRegistrationRequest(MacID: CreateOrReturnSSOID(), UserID: userName)
//       
//            NSLog("\(loginManager.userLoginConfiguration)")
//            NSLog(" [TDS PSSO] UserName \(loginManager.userLoginConfiguration?.loginUserName)")
//            NSLog(" [TDS PSSO] token \(token)")
//            PlatformAuthClass.post(Request, to: "https://auth.thomasdye.net/auth/app/Apple/SSO/extention/Register/User", completion: { (result: Result<TDSUserRegistrationResponse, NetworkError>) in
//                switch result {
//                case .success(let response):
//                    if response.state == true {
//                        NSLog(" [TDS PSSO] User success")
//                        let userLoginConfiguration =  ASAuthorizationProviderExtensionUserLoginConfiguration(loginUserName: response.userName)
////                        userLoginConfiguration.loginUserName = response.userName
////                        loginManager.ssoTokens = ["UserToken" : "this is a test"]
//                        NSLog(" [TDS PSSO] userLoginConfiguration \(userLoginConfiguration)")
//                        do {
//                            try loginManager.saveUserLoginConfiguration(userLoginConfiguration)
//                        } catch let error {
//                            NSLog(" [TDS PSSO] saveUserLoginConfiguration \(error)")
//                        }
//                        
//                        completion(.success)
//                    }
//                case .failure(let error):
//                    NSLog(" [TDS PSSO] error 1 \(error)")
//                    completion(.failed)
//                }
//            })
//            
//        } else {
//            NSLog(" [TDS PSSO] userInterfaceRequired")
//            completion(.userInterfaceRequired)
//        }
//    }
    

     func supportedGrantTypes() -> ASAuthorizationProviderExtensionSupportedGrantTypes {
         return .password
    }
    
    
    func CreateOrReturnSSOID() -> String {
        if let ID = UserDefaults.standard.string(forKey: "SSOID") {
            return ID
        }
        let ID = UUID().uuidString
        UserDefaults.standard.set(ID, forKey: "SSOID")
        return ID
    }
    
    func beginUserRegistration(loginManager: ASAuthorizationProviderExtensionLoginManager, userName: String?, method authenticationMethod: ASAuthorizationProviderExtensionAuthenticationMethod, options: ASAuthorizationProviderExtensionRequestOptions = [], completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void) {

        let loginconfig = ASAuthorizationProviderExtensionUserLoginConfiguration(loginUserName: userName ?? "")
//        loginconfig.loginUserName = userName ?? "test"
        try? loginManager.saveUserLoginConfiguration(loginconfig)
        completion(.success)
    }
func DeviceRegisterRequest(loginConfig:ASAuthorizationProviderExtensionLoginConfiguration,loginManger:ASAuthorizationProviderExtensionLoginManager, token:Auth_token_Saveinfo, completion: @escaping (ASAuthorizationProviderExtensionRegistrationResult) -> Void) {
    do {
        
        try loginManger.saveLoginConfiguration(loginConfig)
//        var SignKeyID = loginManger.identity(for: .currentDeviceSigning)
//        var EncKeyID = loginManger.identity(for: .currentDeviceEncryption)
        let (SignKeyID,DeviceSigningKey, DeviceSigningKeydata) = try getPublicKeyString(from: loginManger.key(for: .currentDeviceSigning)!)!
        let (EncKeyID, DeviceEncryptionKey, DeviceEncryptionKeydata) =  try getPublicKeyString(from: loginManger.key(for: .currentDeviceEncryption)!)!
        let DeviceUUID = CreateOrReturnSSOID()
        
        let request = TDSDeviceRegistrationRequest(DeviceSigningKey: DeviceSigningKey, DeviceEncryptionKey: DeviceEncryptionKey, EncKeyID: EncKeyID, SignKeyID: SignKeyID, DeviceUUID: DeviceUUID,encdata: DeviceEncryptionKeydata,signData: DeviceSigningKeydata)
        NSLog(" [TDS PSSO] \(request)")
        
        PlatformAuthClass.post(request, to: "https://auth.thomasdye.net:1443/register", completion: { (result: Result<TDSDeviceRegistrationResponse, NetworkError>) in
                completion(.success)
        })
        
    } catch  {
        NSLog(" [TDS PSSO] \(error)")
    }
    
    
    
    
    
    
    
//    
//        let Request = TDSDeviceRegistrationRequest(tokenEndpointURL: loginConfig.tokenEndpointURL.absoluteString, jwksEndpointURL: loginConfig.jwksEndpointURL.absoluteString, clientID: loginConfig.clientID, issuer: loginConfig.issuer, audience: loginConfig.audience,MacID: CreateOrReturnSSOID(),DeviceSigningKey: convertSecKeyToString(loginManger.key(for: .currentDeviceSigning)),DeviceEncryptionKey: convertSecKeyToString(loginManger.key(for: .currentDeviceEncryption)),SignKeyID: "",EncKeyID: "")
//        
//        NSLog(" [TDS PSSO] currentDeviceSigning \(loginManger.key(for: .currentDeviceSigning))")
////        Request.DeviceSigningKey = convertSecKeyToString(loginManger.key(for: .currentDeviceSigning))
////        Request.DeviceEncryptionKey = convertSecKeyToString(loginManger.key(for: .currentDeviceEncryption))
//        
//        
//        PlatformAuthClass.post(Request, to: "https://auth.thomasdye.net/auth/app/Apple/SSO/extention/Register/Device", completion: { (result: Result<TDSDeviceRegistrationResponse, NetworkError>) in
//            switch result {
//            case .success(let response):
//                if response.state == true {
//                    NSLog(" [TDS PSSO] User success")
//                    let userLoginConfiguration = loginManger.userLoginConfiguration ??  ASAuthorizationProviderExtensionUserLoginConfiguration(loginUserName: "test account")
////                        userLoginConfiguration.loginUserName = response.userName
////                    loginManger.ssoTokens = ["UserToken" : "this is a test"]
//                    NSLog(" [TDS PSSO] userLoginConfiguration \(userLoginConfiguration)")
//                    do {
//                        try loginManger.saveUserLoginConfiguration(userLoginConfiguration)
//                    } catch let error {
//                        NSLog(" [TDS PSSO] saveUserLoginConfiguration \(error)")
//                    }
//                    
//                    NSLog(" [TDS PSSO] success")
//                    completion(.success)
//                }
//            case .failure(let error):
//                NSLog(" [TDS PSSO] error 1 \(error)")
//                completion(.failed)
//            }
//        })
    }
        
    
    
    func convertSecKeyToString(_ secKey: SecKey?) -> String? {
        guard let secKey else {
            NSLog(" [TDS PSSO] secKey error 1")
            return nil
        }
        NSLog(" [TDS PSSO] secKey1")
        // Extract the public key data
        guard let publicKeyData = SecKeyCopyExternalRepresentation(secKey, nil) else {
            NSLog(" [TDS PSSO] secKey error 2")
            return nil
        }

        // Convert the key data to a Base64 encoded string
        let keyData = publicKeyData as Data
        NSLog(" [TDS PSSO] secKey data1")
        let base64EncodedKey = keyData.base64EncodedString()

        return base64EncodedKey
    }
    
    func protocolVersion() -> ASAuthorizationProviderExtensionPlatformSSOProtocolVersion {
        return .version2_0
    }
    
    func registrationDidComplete() {
        NSLog(" [TDS PSSO]  registrationDidComplete")
    }
    
    func registrationDidCancel() {
        NSLog(" [TDS PSSO]  registrationDidCancel")
    }
    
    func keyWillRotate(
        for keyType: ASAuthorizationProviderExtensionKeyType,
        newKey: SecKey,
        loginManager: ASAuthorizationProviderExtensionLoginManager,
        completion: @escaping (Bool) -> Void
    ) {
        NSLog(" [TDS PSSO]  keyWillRotate \(keyType)")
        completion(false)
    }
    var supportedDeviceEncryptionAlgorithms: [ASAuthorizationProviderExtensionEncryptionAlgorithm] {
            // Return the encryption algorithms your extension supports
            return [
//                .hpke_P256_SHA256_AES_GCM_256,
                .ecdhe_A256GCM
            ]
        }
    var supportedUserSecureEnclaveKeySigningAlgorithms: [ASAuthorizationProviderExtensionSigningAlgorithm] {
            // Return the encryption algorithms your extension supports
            return [
                .ed25519
            ]
        }
    var supportedDeviceSigningAlgorithms: [ASAuthorizationProviderExtensionSigningAlgorithm] {
        return [
            .ed25519
        ]
    }

    func getPublicKey(from privateKey: SecKey) -> SecKey? {
        // Use SecKeyCopyPublicKey to get the public key from the private key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            NSLog(" [TDS PSSO] Error: Could not get public key from private key")
            return nil
        }
        
        return publicKey
    }
    
    // Function to compute the SHA-256 hash of the public key data and return it as a hex string
    func getKeyID(from publicKeyDERData: Data) throws -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        publicKeyDERData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(publicKeyDERData.count), &hash)
        }
        let hashData = Data(hash)
        return hashData.map { String(format: "%02hhx", $0) }.joined() // Hexadecimal string
    }

    // Function to build an ASN.1 header based on the key type (RSA, EC)
    func addX509Header(to publicKeyDERData: Data, keyType: CFString) -> Data {
        var header: [UInt8] = []
        
        if keyType == kSecAttrKeyTypeRSA {
            // Header for RSA (OID: 1.2.840.113549.1.1.1)
            header = [
                0x30, 0x82, 0x01, 0x22, // SEQUENCE (SubjectPublicKeyInfo)
                0x30, 0x0D,             // SEQUENCE (AlgorithmIdentifier)
                0x06, 0x09,             // OBJECT IDENTIFIER (1.2.840.113549.1.1.1 -> rsaEncryption)
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
                0x05, 0x00,             // NULL (Parameters)
                0x03, 0x82, 0x01, 0x0F, // BIT STRING
                0x00                    // Unused bits indicator for BIT STRING
            ]
        } else if keyType == kSecAttrKeyTypeEC {
            // Header for EC (OID: 1.2.840.10045.2.1 for ecPublicKey with secp256r1 curve OID: 1.2.840.10045.3.1.7)
            header = [
                0x30, 0x59,             // SEQUENCE (SubjectPublicKeyInfo)
                0x30, 0x13,             // SEQUENCE (AlgorithmIdentifier)
                0x06, 0x07,             // OBJECT IDENTIFIER (1.2.840.10045.2.1 -> ecPublicKey)
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                0x06, 0x08,             // OBJECT IDENTIFIER (1.2.840.10045.3.1.7 -> secp256r1)
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
                0x03, 0x42,             // BIT STRING
                0x00                    // Unused bits indicator for BIT STRING
            ]
        }
        
        // Add the header to the public key data
        var x509PublicKey = Data(header)
        x509PublicKey.append(publicKeyDERData)
        
        return x509PublicKey
    }

    // Function to extract the public key as PEM format and compute the Key ID
    func getPublicKeyString(from privateKey: SecKey) throws -> (String, String, Data)? {
        // Get the public key from the private key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return nil
        }
        
        // Determine the type of the key (RSA, EC, etc.)
        let attributes = SecKeyCopyAttributes(publicKey) as! [CFString: Any]
        let keyType = attributes[kSecAttrKeyType] as! CFString
        
        // Extract public key data in DER format
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            if let cfError = error?.takeRetainedValue() {
                throw cfError as Error
            }
            return nil
        }
        
        let publicKeyDERData = publicKeyData as Data
        
        // Add the X.509 header to the raw public key data based on its type (RSA or EC)
        let x509PublicKeyData = addX509Header(to: publicKeyDERData, keyType: keyType)
        
        // Convert X.509 DER data to base64-encoded PEM format
        let publicKeyString = x509PublicKeyData.base64EncodedString(options: [.lineLength64Characters])
        
        // Wrap the base64 encoded string with PEM headers
        let publicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        \(publicKeyString)
        -----END PUBLIC KEY-----
        """
        
        // Compute Key ID (SHA-256 hash of the X.509 public key data)
        let keyID = try getKeyID(from: publicKeyDERData)
        
        // Return both keyID, PEM encoded public key, and X.509 DER format
        return (keyID, publicKeyPEM, x509PublicKeyData)
    }
 
}

struct TDSDeviceRegistrationRequest:Encodable {
        let DeviceSigningKey: String
        let DeviceEncryptionKey: String
        let EncKeyID: String
        let SignKeyID: String
        let DeviceUUID: String
        let encdata:Data
        let signData:Data
}

// Define a response model (e.g., authentication response)
struct TDSDeviceRegistrationResponse: Codable {
    let state:Bool
}


struct TDSUserRegistrationRequest:Codable {
    
    var MacID:String
    var UserID:String?
    
}

struct TDSUserRegistrationResponse: Codable {
    let state:Bool
    let userName:String
    
}
