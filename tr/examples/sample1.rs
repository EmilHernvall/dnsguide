use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    /// Bu, paket içeriğini tutmak için bize taze bir tampon ve nerede
    /// olduğumuzu takip edecek bir alan sağlar.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Tampon içindeki mevcut konum
    fn pos(&self) -> usize {
        self.pos
    }

    /// Tampon konumunu belirli sayıda adım ileri al
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Tampon konumunu değiştir
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Tek bir bayt oku ve konumu bir adım ileri al
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Konumu değiştirmeden tek bir bayt al
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Bir bayt aralığı al
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// İki bayt oku, iki adım ileri git
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Dört bayt oku, dört adım ileri git
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Bir qname oku
    ///
    /// Zor kısım: Etiketleri hesaba katarak alan adlarını okumak.
    /// [3]www[6]google[3]com[0] gibi bir şey alıp outstr'ye
    /// www.google.com olarak ekleyecek.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Atlama ile karşılaşabileceğimiz için, konumumuzu struct içindeki
        // konum yerine yerel olarak takip edeceğiz. Bu, ortak konumu mevcut
        // qname'imizin ötesindeki bir noktaya taşıyabilmemizi sağlarken,
        // bu değişkeni kullanarak mevcut qname üzerindeki ilerlememizi takip
        // etmemize izin verir.
        let mut pos = self.pos();

        // atlayıp atlamadığımızı izler
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Her etiket için eklediğimiz ayırıcı. Alan adının başında nokta
        // olmasını istemediğimiz için şimdilik boş bırakacağız ve ilk yinelemenin
        // sonunda "." yapacağız.
        let mut delim = "";
        loop {
            // DNS paketleri güvenilmeyen verilerdir, bu yüzden paranoid olmamız
            // gerekir. Birisi atlama yönergelerinde döngü içeren bir paket
            // oluşturabilir. Bu, böyle paketlere karşı koruma sağlar.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // Şu anda her zaman bir etiketin başındayız. Etiketlerin bir uzunluk
            // baytı ile başladığını hatırlayın.
            let len = self.get(pos)?;

            // Eğer len'in en anlamlı iki biti ayarlıysa, başka bir ofsete atlamayı
            // temsil eder:
            if (len & 0xC0) == 0xC0 {
                // Geçerli etiketten sonraki konuma ilerlemek için tampon
                // konumunu güncelle. Bir daha dokunmamıza gerek yok.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Başka bir bayt oku, ofseti hesapla ve yerel konum değişkenini
                // güncelleyerek atlamayı gerçekleştir.
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Bir atlama yapıldığını belirt.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // Tek bir etiketi okuyup çıktıya eklediğimiz temel durum:
            else {
                // Uzunluk baytını geçmek için bir bayt ileri git.
                pos += 1;

                // Alan adları uzunluğu 0 olan boş bir etiketle biter,
                // bu yüzden uzunluk sıfırsa işimiz bitti.
                if len == 0 {
                    break;
                }

                // Önce ayırıcıyı çıktı tamponumuza ekle.
                outstr.push_str(delim);

                // Bu etiket için gerçek ASCII baytlarını çıkar ve çıktıya ekle.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Etiketin tam uzunluğu kadar ileri git.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        // Return the constant header size
        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }
}

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}