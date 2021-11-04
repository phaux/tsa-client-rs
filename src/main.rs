use asn1::{
    parse_single, Asn1Read, Asn1Write, Explicit, GeneralizedTime, IA5String, ObjectIdentifier, Tlv,
};

#[derive(Debug, Asn1Read, Asn1Write)]
struct TimeStampReq<'a> {
    /// The version field (currently v1) describes the version of the Time-Stamp request.
    version: u8,

    /// A hash algorithm OID and the hash value of the data to be time-stamped.
    /// The messageImprint field SHOULD contain the hash of the datum to be
    /// time-stamped.  The hash is represented as an OCTET STRING.  Its
    /// length MUST match the length of the hash value for that algorithm
    /// (e.g., 20 bytes for SHA-1 or 16 bytes for MD5).
    message_imprint: MessageImprint<'a>,

    /// The reqPolicy field, if included, indicates the TSA policy under
    /// which the TimeStampToken SHOULD be provided.
    req_policy: Option<ObjectIdentifier<'a>>,

    /// The nonce, if included, allows the client to verify the timeliness of
    /// the response when no local clock is available.  The nonce is a large
    /// random number with a high probability that the client generates it
    /// only once (e.g., a 64 bit integer).  In such a case the same nonce
    /// value MUST be included in the response, otherwise the response shall
    /// be rejected.
    nonce: Option<u64>,

    /// If the certReq field is present and set to true, the TSA's public key
    /// certificate that is referenced by the ESSCertID identifier inside a
    /// SigningCertificate attribute in the response MUST be provided by the
    /// TSA in the certificates field from the SignedData structure in that
    /// response.  That field may also contain other certificates.
    /// If the certReq field is missing or if the certReq field is present
    /// and set to false then the certificates field from the SignedData
    /// structure MUST not be present in the response.
    #[default(false)]
    cert_req: bool,
    // FIXME: doesn't compile
    // /// The extensions field is a generic way to add additional information
    // /// to the request in the future.  Extensions is defined in [RFC 2459].
    // /// If an extension, whether it is marked critical or not critical, is
    // /// used by a requester but is not recognized by a time-stamping server,
    // /// the server SHALL not issue a token and SHALL return a failure
    // /// (unacceptedExtension).
    // extensions: Option<Implicit<'a, Tlv<'a>, 0>>,
}

#[derive(Debug, Asn1Read, Asn1Write)]
struct MessageImprint<'a> {
    /// The hash algorithm indicated in the hashAlgorithm field SHOULD be a
    /// known hash algorithm (one-way and collision resistant).  That means
    /// that it SHOULD be one-way and collision resistant.  The Time Stamp
    /// Authority SHOULD check whether or not the given hash algorithm is
    /// known to be "sufficient" (based on the current state of knowledge in
    /// cryptanalysis and the current state of the art in computational
    /// resources, for example).  If the TSA does not recognize the hash
    /// algorithm or knows that the hash algorithm is weak (a decision left
    /// to the discretion of each individual TSA), then the TSA SHOULD refuse
    /// to provide the time-stamp token by returning a pkiStatusInfo of
    /// 'bad_alg'.
    hash_algorithm: AlgorithmIdentifier<'a>,

    hashed_message: &'a [u8],
}

#[derive(Debug, Asn1Read, Asn1Write)]
struct AlgorithmIdentifier<'a> {
    algorithm: ObjectIdentifier<'a>,
    parameters: Tlv<'a>,
}

#[derive(Debug, Asn1Read, Asn1Write)]
struct TimeStampResp<'a> {
    status: PKIStatusInfo<'a>,
    time_stamp_token: Option<ContentInfo<'a>>,
}

#[derive(Debug, Asn1Read, Asn1Write)]
struct PKIStatusInfo<'a> {
    status: u8,

    /// The statusString field of PKIStatusInfo MAY be used to include reason
    /// text such as "messageImprint field is not correctly formatted".
    status_string: Option<IA5String<'a>>,

    fail_info: Option<u8>,
}

#[derive(Debug)]
enum PKIStatus {
    /// when the PKIStatus contains the value zero a TimeStampToken, as requested, is present.
    Granted = 0,

    /// when the PKIStatus contains the value one a TimeStampToken, with modifications, is present.
    GrantedWithMods = 1,

    Rejection = 2,

    Waiting = 3,

    /// this message contains a warning that a revocation is imminent
    RevocationWarning = 4,

    /// notification that a revocation has occurred
    RevocationNotification = 5,
}

/// When the TimeStampToken is not present, the failInfo indicates the
/// reason why the time-stamp request was rejected and may be one of the
/// following values.
#[derive(Debug)]
enum PKIFailureInfo {
    /// unrecognized or unsupported Algorithm Identifier
    BadAlg = 0,

    /// transaction not permitted or supported
    BadRequest = 2,

    /// the data submitted has the wrong format
    BadDataFormat = 5,

    /// the TSA's time source is not available
    TimeNotAvailable = 14,

    /// the requested TSA policy is not supported by the TSA
    UnacceptedPolicy = 15,

    /// the requested extension is not supported by the TSA
    UnacceptedExtension = 16,

    /// the additional information requested could not be understood
    /// or is not available
    AddInfoNotAvailable = 17,

    /// the request cannot be handled due to system failure
    SystemFailure = 25,
}

#[derive(Debug, Asn1Read, Asn1Write)]
struct ContentInfo<'a> {
    content_type: ObjectIdentifier<'a>,
    content: Explicit<'a, Tlv<'a>, 0>,
}

#[derive(Debug, Asn1Read, Asn1Write)]
struct TSTInfo<'a> {
    version: u8,
    policy: Option<ObjectIdentifier<'a>>,
    message_imprint: MessageImprint<'a>,
    serial_number: u64,
    gen_time: GeneralizedTime,
    accuracy: Option<Accuracy>,
    #[default(false)]
    ordering: bool,
    nonce: Option<u64>,
    tsa: Option<Explicit<'a, GeneralName<'a>, 0>>,
    extensions: Option<Explicit<'a, Tlv<'a>, 1>>,
}

#[derive(Debug, Asn1Read, Asn1Write)]
struct Accuracy {
    seconds: Option<u32>,
    millis: Option<u32>,
    micros: Option<u32>,
}

#[derive(Debug, Asn1Read, Asn1Write)]
#[non_exhaustive]
enum GeneralName<'a> {
    OtherName(Explicit<'a, Tlv<'a>, 0>),
    DNSName(Explicit<'a, IA5String<'a>, 2>),
    UniformResourceIdentifier(Explicit<'a, IA5String<'a>, 6>),
    IPAddress(Explicit<'a, &'a [u8], 7>),
    RegisteredID(Explicit<'a, ObjectIdentifier<'a>, 8>),
}

fn main() {
    let query = std::fs::read("data/file.tsq").unwrap();
    let query: TimeStampReq = parse_single(&query).unwrap();
    dbg!(query);

    let resp = std::fs::read("data/file.tsr").unwrap();
    let resp: TimeStampResp = parse_single(&resp).unwrap();
    dbg!(resp.status);
}
