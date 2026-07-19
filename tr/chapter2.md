Bölüm 2 - Bir stub resolver oluşturmak
======================================

DNS paketlerini başarıyla ayrıştırabiliyor olmak biraz tatmin edici olsa da,
onları yalnızca diskten okumak pek işe yaramaz. Sıradaki adım olarak,
`stub resolver` adı verilen bir yapı kuracağız. Bu, özyinelemeli çözüm için
yerleşik desteği olmayan ve yalnızca bunu sağlayan bir DNS sunucusuyla çalışan
bir DNS istemcisidir. Daha sonra gerçek bir recursive resolver uygulayarak
sunucuya bağımlılığı ortadan kaldıracağız.

### BytePacketBuffer'ı yazma için genişletmek

Bir sorguya yanıt verebilmek için yalnızca paket okuyabilmemiz değil, onları
yazabilmemiz de gerekir. Bunun için `BytePacketBuffer` yapısını birkaç ek
metotla genişletmemiz gerekiyor:

```rust
impl BytePacketBuffer {

	- snip -

	fn write(&mut self, val: u8) -> Result<()> {
		if self.pos >= 512 {
			return Err("End of buffer".into());
		}
		self.buf[self.pos] = val;
		self.pos += 1;
		Ok(())
	}

	fn write_u8(&mut self, val: u8) -> Result<()> {
		self.write(val)?;

		Ok(())
	}

	fn write_u16(&mut self, val: u16) -> Result<()> {
		self.write((val >> 8) as u8)?;
		self.write((val & 0xFF) as u8)?;

		Ok(())
	}

	fn write_u32(&mut self, val: u32) -> Result<()> {
		self.write(((val >> 24) & 0xFF) as u8)?;
		self.write(((val >> 16) & 0xFF) as u8)?;
		self.write(((val >> 8) & 0xFF) as u8)?;
		self.write(((val >> 0) & 0xFF) as u8)?;

		Ok(())
	}
```

Etiketlenmiş biçimde sorgu adları yazmak için de bir fonksiyona ihtiyacımız
olacak:

```rust
	fn write_qname(&mut self, qname: &str) -> Result<()> {
		for label in qname.split('.') {
			let len = label.len();
			if len > 0x3f {
				return Err("Single label exceeds 63 characters of length".into());
			}

			self.write_u8(len as u8)?;
			for b in label.as_bytes() {
				self.write_u8(*b)?;
			}
		}

		self.write_u8(0)?;

		Ok(())
	}

} // End of BytePacketBuffer
```

### DnsHeader'ı yazma için genişletmek

Yeni fonksiyonlarımızın üzerine kurarak protokol temsil eden yapıların yazma
kısmını da ekleyebiliriz. Önce `DnsHeader` ile başlayalım:

```rust
impl DnsHeader {

	- snip -

	pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
		buffer.write_u16(self.id)?;

		buffer.write_u8(
			(self.recursion_desired as u8)
				| ((self.truncated_message as u8) << 1)
				| ((self.authoritative_answer as u8) << 2)
				| (self.opcode << 3)
				| ((self.response as u8) << 7) as u8,
		)?;

		buffer.write_u8(
			(self.rescode as u8)
				| ((self.checking_disabled as u8) << 4)
				| ((self.authed_data as u8) << 5)
				| ((self.z as u8) << 6)
				| ((self.recursion_available as u8) << 7),
		)?;

		buffer.write_u16(self.questions)?;
		buffer.write_u16(self.answers)?;
		buffer.write_u16(self.authoritative_entries)?;
		buffer.write_u16(self.resource_entries)?;

		Ok(())
	}

}
```

### DnsQuestion'ı yazma için genişletmek

Sırada `DnsQuestion` var:

```rust
impl DnsQuestion {

	- snip -

	pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
		buffer.write_qname(&self.name)?;

		let typenum = self.qtype.to_num();
		buffer.write_u16(typenum)?;
		buffer.write_u16(1)?;

		Ok(())
	}

}
```

### DnsRecord'ı yazma için genişletmek

`DnsRecord` şimdilik oldukça kompakt; ancak farklı kayıt türlerini ele almak
için burada zamanla epey kod ekleyeceğiz:

```rust
impl DnsRecord {

	- snip -

	pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
		let start_pos = buffer.pos();

		match *self {
			DnsRecord::A {
				ref domain,
				ref addr,
				ttl,
			} => {
				buffer.write_qname(domain)?;
				buffer.write_u16(QueryType::A.to_num())?;
				buffer.write_u16(1)?;
				buffer.write_u32(ttl)?;
				buffer.write_u16(4)?;

				let octets = addr.octets();
				buffer.write_u8(octets[0])?;
				buffer.write_u8(octets[1])?;
				buffer.write_u8(octets[2])?;
				buffer.write_u8(octets[3])?;
			}
			DnsRecord::UNKNOWN { .. } => {
				println!("Skipping record: {:?}", self);
			}
		}

		Ok(buffer.pos() - start_pos)
	}

}
```

### DnsPacket'ı yazma için genişletmek

Bunların hepsini `DnsPacket` içinde bir araya getirelim:

```rust
impl DnsPacket {

	- snip -

	pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
		self.header.questions = self.questions.len() as u16;
		self.header.answers = self.answers.len() as u16;
		self.header.authoritative_entries = self.authorities.len() as u16;
		self.header.resource_entries = self.resources.len() as u16;

		self.header.write(buffer)?;

		for question in &self.questions {
			question.write(buffer)?;
		}
		for rec in &self.answers {
			rec.write(buffer)?;
		}
		for rec in &self.authorities {
			rec.write(buffer)?;
		}
		for rec in &self.resources {
			rec.write(buffer)?;
		}

		Ok(())
	}

}
```

### Bir stub resolver uygulamak

Artık stub resolver'ımızı uygulamaya hazırız. Rust, işin büyük kısmını yapan
kolay bir `UDPSocket` sağlar.

```rust
fn main() -> Result<()> {
	// google.com için A sorgusu yap
	let qname = "google.com";
	let qtype = QueryType::A;

	// Google'ın herkese açık DNS sunucusunu kullan
	let server = ("8.8.8.8", 53);

	// UDP soketini rastgele bir porta bağla
	let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

	// Sorgu paketimizi oluştur. `recursion_desired` bayrağını ayarlamayı
	// unutmadığımızdan emin olmamız önemli. Daha önce belirtildiği gibi, paket
	// kimliği keyfidir.
	let mut packet = DnsPacket::new();

	packet.header.id = 6666;
	packet.header.questions = 1;
	packet.header.recursion_desired = true;
	packet
		.questions
		.push(DnsQuestion::new(qname.to_string(), qtype));

	// Yeni write metodumuzu kullanarak paketi bir tampona yaz...
	let mut req_buffer = BytePacketBuffer::new();
	packet.write(&mut req_buffer)?;

	// ...ve soketimizle sunucuya gönder:
	socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

	// Yanıtı almak için yeni bir `BytePacketBuffer` oluşturacağız ve soketten
	// yanıtı doğrudan bu tampona yazmasını isteyeceğiz.
	let mut res_buffer = BytePacketBuffer::new();
	socket.recv_from(&mut res_buffer.buf)?;

	// Önceki bölümde olduğu gibi, paketi gerçekten ayrıştırmak için
	// `DnsPacket::from_buffer()` kullanılır; ardından yanıtı yazdırabiliriz.
	let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
	println!("{:#?}", res_packet.header);

	for q in res_packet.questions {
		println!("{:#?}", q);
	}
	for rec in res_packet.answers {
		println!("{:#?}", rec);
	}
	for rec in res_packet.authorities {
		println!("{:#?}", rec);
	}
	for rec in res_packet.resources {
		println!("{:#?}", rec);
	}

	Ok(())
}
```

Çalıştırdığımızda şu çıktı alınır:

```text
DnsHeader {
	id: 6666,
	recursion_desired: true,
	truncated_message: false,
	authoritative_answer: false,
	opcode: 0,
	response: true,
	rescode: NOERROR,
	checking_disabled: false,
	authed_data: false,
	z: false,
	recursion_available: true,
	questions: 1,
	answers: 1,
	authoritative_entries: 0,
	resource_entries: 0
}
DnsQuestion {
	name: "google.com",
	qtype: A
}
A {
	domain: "google.com",
	addr: 216.58.209.110,
	ttl: 79
}
```

Bir sonraki bölüm daha zengin bir kayıt türü kümesini ele alıyor: [Bölüm 3 - Daha fazla kayıt türü eklemek](chapter3.md)