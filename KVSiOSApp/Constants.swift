import Foundation
import AWSCognitoIdentityProvider

// Cognito constants
let awsCognitoUserPoolsSignInProviderKey = "UserPool"

let cognitoIdentityUserPoolRegion = AWSRegionType.USWest2
let cognitoIdentityUserPoolId = "us-west-2_zm6JHOwJ7"
let cognitoIdentityUserPoolAppClientId = "h94hm95mpno0k3ejsgo2f2voj"
let cognitoIdentityUserPoolAppClientSecret = "nq7qglgvm34apblipb2c65s9c4kgll24kij84u9u1fh9u8t1oo1"
let cognitoIdentityPoolId = "us-west-2:2841f1ab-9b8e-4030-b8d6-30e8253973a6"

// KinesisVideo constants
let awsKinesisVideoKey = "kinesisvideo"
let videoProtocols =  ["WSS", "HTTPS"]

// Connection constants
let connectAsMasterKey = "connect-as-master"
let connectAsViewerKey = "connect-as-viewer"

let masterRole = "MASTER"
let viewerRole = "VIEWER"
let connectAsViewClientId = "ConsumerViewer"

// AWSv4 signer constants
let signerAlgorithm = "AWS4-HMAC-SHA256"
let awsRequestTypeKey = "aws4_request"
let xAmzAlgorithm = "X-Amz-Algorithm"
let xAmzCredential = "X-Amz-Credential"
let xAmzDate = "X-Amz-Date"
let xAmzExpiresKey = "X-Amz-Expires"
let xAmzExpiresValue = "299"
let xAmzSecurityToken = "X-Amz-Security-Token"
let xAmzSignature = "X-Amz-Signature"
let xAmzSignedHeaders = "X-Amz-SignedHeaders"
let newlineDelimiter = "\n"
let slashDelimiter = "/"
let colonDelimiter = ":"
let plusDelimiter = "+"
let equalsDelimiter = "="
let ampersandDelimiter = "&"
let restMethod = "GET"
let utcDateFormatter = "yyyyMMdd'T'HHmmss'Z'"
let utcTimezone = "UTC"

let hostKey = "host"
let wssKey = "wss"

let plusEncoding = "%2B"
let equalsEncoding = "%3D"

