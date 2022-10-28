use pktparse::ethernet::MacAddress;
use pktparse::icmp::IcmpCode;


// funzioni di supporto per conversione
pub fn string_from_icmpcode(code: IcmpCode) -> String{

    let code_name = match code {
        IcmpCode::EchoReply => {"Echo Reply"}
        IcmpCode::Reserved => {"Reserved"}
        IcmpCode::DestinationUnreachable(_) => {"DestinationUnreachable"}
        IcmpCode::SourceQuench => {"SourceQuench"}
        IcmpCode::Redirect(_) => {"Redirect"}
        IcmpCode::EchoRequest => {"EchoRequest"}
        IcmpCode::RouterAdvertisment => {"RouterAdvertisment"}
        IcmpCode::RouterSolicication => {"RouterSolicication"}
        IcmpCode::TimeExceeded(_) => {"TimeExceeded"}
        IcmpCode::ParameterProblem(_) => {"ParameterProblem"}
        IcmpCode::Timestamp => {"Timestamp"}
        IcmpCode::TimestampReply => {"TimestampReply"}
        IcmpCode::ExtendedEchoRequest => {"ExtendedEchoRequest"}
        IcmpCode::ExtendedEchoReply(_) => {"ExtendedEchoReply"}
        IcmpCode::Other(_) => {"Other"}
    };
    String::from(code_name)
}

pub fn hex_from_u8(u: u8) -> Option<char>{
    let res;
    match u {
        0 => res = Some('0'),
        1 => res = Some('1'),
        2 => res = Some('2'),
        3 => res = Some('3'),
        4 => res = Some('4'),
        5 => res = Some('5'),
        6 => res = Some('6'),
        7 => res = Some('7'),
        8 => res = Some('8'),
        9 => res = Some('9'),
        10 => res = Some('A'),
        11 => res = Some('B'),
        12 => res = Some('C'),
        13 => res = Some('D'),
        14 => res = Some('E'),
        15 => res = Some('F'),
        _ => res = None
    }
    res
}

pub fn string_from_mac(mac: MacAddress) ->String{

    let res = format!("{}{}:{}{}:{}{}:{}{}:{}{}:{}{}",
                      hex_from_u8(mac.0[0]/16).unwrap(), hex_from_u8(mac.0[0]%16).unwrap(),
                      hex_from_u8(mac.0[1]/16).unwrap(), hex_from_u8(mac.0[1]%16).unwrap(),
                      hex_from_u8(mac.0[2]/16).unwrap(), hex_from_u8(mac.0[2]%16).unwrap(),
                      hex_from_u8(mac.0[3]/16).unwrap(), hex_from_u8(mac.0[3]%16).unwrap(),
                      hex_from_u8(mac.0[4]/16).unwrap(), hex_from_u8(mac.0[4]%16).unwrap(),
                      hex_from_u8(mac.0[5]/16).unwrap(), hex_from_u8(mac.0[5]%16).unwrap(),
    ).as_str().to_string();

    res
}