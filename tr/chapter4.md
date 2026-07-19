Bölüm 4 - İlk DNS sunucumuz
===========================

Buraya kadar geldiysek, artık ilk gerçek sunucu yazma denememizi yapmaya
hazırız. Gerçek DNS sunucuları iki farklı türde gelir:

 * Yetkili Sunucu - Bir veya daha fazla "zone" barındıran DNS sunucusu.
   Örneğin google.com bölgesi için yetkili sunucular ns1.google.com,
   ns2.google.com, ns3.google.com ve ns4.google.com'dur.
 * Önbellekleyen Sunucu - Önce kendi önbelleğini kontrol ederek istenen kaydı
   zaten biliyor mu diye bakan, bilmiyorsa da sonucu öğrenmek için özyinelemeli
   arama yapan bir DNS sunucusu. Buna ev yönlendiricinizde çalışan DNS sunucusu
   da, ISS'nizin DHCP ile size atadığı DNS sunucusu da, Google'ın herkese açık
   DNS sunucuları 8.8.8.8 ve 8.8.4.4 de dahildir.

Teknik olarak bir sunucunun her iki işi birden yapmasına engel yoktur, ancak
pratikte bu iki rol genellikle birbirini dışlar. Bu aynı zamanda paket
başlığındaki `RD` (Recursion Desired / Özyineleme İsteği) ve `RA` (Recursion
Available / Özyineleme Uygun) bayraklarının önemini açıklar -- bir stub
resolver, önbellekleyen bir sunucuya sorgu yaparken `RD` bayrağını ayarlar ve
sunucu bu tür sorgulara izin verdiği için aramayı yapar ve `RA` bayrağı ayarlı
bir yanıt gönderir. Yetkili bir sunucuda bu çalışmaz; çünkü yalnızca barındırdığı
zone'larla ilgili sorgulara yanıt verir ve bu nedenle `RD` bayrağı ayarlı tüm
sorgulara bir hata yanıtı döndürür.

Ama bunun için sadece bana güvenmeyin! Bunun gerçekten böyle olup olmadığını
doğrulayalım. Önce `yahoo.com` için arama yapmak üzere `8.8.8.8` kullanalım:

```text
# dig @8.8.8.8 yahoo.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +recurse @8.8.8.8 yahoo.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53231
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;yahoo.com.			IN	A

;; ANSWER SECTION:
yahoo.com.		1051	IN	A	98.138.253.109
yahoo.com.		1051	IN	A	98.139.183.24
yahoo.com.		1051	IN	A	206.190.36.45

;; Query time: 1 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Fri Jul 08 11:43:55 CEST 2016
;; MSG SIZE  rcvd: 86
```

Bu beklediğimiz gibi çalışıyor. Şimdi aynı sorguyu `google.com` bölgesini
barındıran sunuculardan birine gönderelim:

```text
# dig @ns1.google.com yahoo.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +recurse @ns1.google.com yahoo.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 12034
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;yahoo.com.			IN	A

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 11:44:07 CEST 2016
;; MSG SIZE  rcvd: 27
```

Yanıtın durumunun `REFUSED` dediğine dikkat edin! `dig` ayrıca, sorguda `RD`
bayrağı ayarlı olmasına rağmen sunucunun yanıtında `RA` bayrağını ayarlamadığını
bize bildirir. Yine de aynı sunucuyu `google.com` için kullanabiliriz:

```text
dig @ns1.google.com google.com                                                                                                                                                                                                                                 <<<

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +recurse @ns1.google.com google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28058
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		300	IN	A	216.58.211.142

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 11:46:27 CEST 2016
;; MSG SIZE  rcvd: 44
```

Bu sefer hata yok -- ancak `dig` hâlâ özyinelemenin kullanılamadığını söylüyor.
Uyarıyı `+norecurse` ile açıkça kapatabiliriz:

```text
# dig +norecurse @ns1.google.com google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @ns1.google.com google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15850
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		300	IN	A	216.58.211.142

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 11:47:52 CEST 2016
;; MSG SIZE  rcvd: 44
```

Bu son sorgu, özyinelemeli çözümün bir parçası olarak önbellekleyen bir
sunucudan bekleyeceğimiz türdendir.

Kendi sunucumuzu yazmaya ilk girişimizde, bundan da daha basit bir şey yapıp
sorguları başka bir önbellekleyen sunucuya ileten bir sunucu uygulayacağız;
yani bir "DNS proxy sunucusu". Zaten zor işin büyük kısmını yaptık, bu yüzden
oldukça hızlı ilerleyecek!

### Aramayı ayrı bir işleve ayırmak

Kısa bir refaktörleme ile başlayacağız ve arama kodumuzu ayrı bir işleve
taşıyacağız. Bu, büyük ölçüde önceki bölümde `main` fonksiyonumuzda yer alan
kodun aynısıdır.

```rust
fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
	// Sorguları Google'ın herkese açık DNS'ine ilet
	let server = ("8.8.8.8", 53);

	let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

	let mut packet = DnsPacket::new();

	packet.header.id = 6666;
	packet.header.questions = 1;
	packet.header.recursion_desired = true;
	packet
		.questions
		.push(DnsQuestion::new(qname.to_string(), qtype));

	let mut req_buffer = BytePacketBuffer::new();
	packet.write(&mut req_buffer)?;
	socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

	let mut res_buffer = BytePacketBuffer::new();
	socket.recv_from(&mut res_buffer.buf)?;

	DnsPacket::from_buffer(&mut res_buffer)
}

```

### İlk sunucumuzu uygulamak

Şimdi sunucu kodumuzu yazacağız. Önce bazı şeyleri düzene sokmamız gerekiyor.

```rust
/// Tek bir gelen paketi işle
fn handle_query(socket: &UdpSocket) -> Result<()> {
	// Elimizde bir soket varken bir paket okuyabiliriz. Bu, bir paket
	// gelene kadar bloklar.
	let mut req_buffer = BytePacketBuffer::new();

	// `recv_from` fonksiyonu veriyi verilen tampona yazar ve okunan verinin
	// uzunluğuyla birlikte kaynak adresi döndürür.
	// Uzunlukla ilgilenmiyoruz; ancak yanıtı daha sonra geri gönderebilmek
	// için kaynağı takip etmemiz gerekiyor.
	let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

	// Sonraki adımda `DnsPacket::from_buffer`, ham baytları bir `DnsPacket`
	// nesnesine dönüştürmek için kullanılır.
	let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

	// Yanıt paketini oluştur ve başlat
	let mut packet = DnsPacket::new();
	packet.header.id = request.header.id;
	packet.header.recursion_desired = true;
	packet.header.recursion_available = true;
	packet.header.response = true;

	// Normal durumda tam olarak bir soru bulunur
	if let Some(question) = request.questions.pop() {
		println!("Received query: {:?}", question);

		// Her şey beklediğimiz gibi kurulduğundan sorguyu hedef sunucuya
		// iletebiliriz. Sorgu başarısız olursa, istemciye bunu belirtmek için
		// `SERVFAIL` yanıt kodu ayarlanır. Her şey planlandığı gibi giderse,
		// soru ve yanıt kayıtları yanıt paketimize kopyalanır.
		if let Ok(result) = lookup(&question.name, question.qtype) {
			packet.questions.push(question);
			packet.header.rescode = result.header.rescode;

			for rec in result.answers {
				println!("Answer: {:?}", rec);
				packet.answers.push(rec);
			}
			for rec in result.authorities {
				println!("Authority: {:?}", rec);
				packet.authorities.push(rec);
			}
			for rec in result.resources {
				println!("Resource: {:?}", rec);
				packet.resources.push(rec);
			}
		} else {
			packet.header.rescode = ResultCode::SERVFAIL;
		}
	}
	// Rastgele göndericilerden gelen giriş verisinin ne kadar güvenilmez
	// olabileceğini akılda tutarak, gerçekten bir soru olup olmadığını
	// doğrulamamız gerekir. Eğer yoksa, gönderenin bir hata yaptığını belirtmek
	// için `FORMERR` döndürürüz.
	else {
		packet.header.rescode = ResultCode::FORMERR;
	}

	// Geriye yalnızca yanıtı kodlayıp göndermek kalıyor!
	let mut res_buffer = BytePacketBuffer::new();
	packet.write(&mut res_buffer)?;

	let len = res_buffer.pos();
	let data = res_buffer.get_range(0, len)?;

	socket.send_to(data, src)?;

	Ok(())
}

fn main() -> Result<()> {
	// 2053 portunda bir UDP soketi bağla
	let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

	// Şimdilik sorgular sıralı ele alınıyor, bu yüzden istekleri servis etmek
	// için sonsuz bir döngü başlatıyoruz.
	loop {
		match handle_query(&socket) {
			Ok(_) => {}
			Err(e) => eprintln!("An error occurred: {}", e),
		}
	}
}
```

Hata işleme için `match` kalıbı burada tekrar tekrar kullanılıyor; çünkü istek
döngümüzün hiçbir koşulda sonlanmasını istemiyoruz. Biraz uzun görünüyor ve
normalde bunun yerine `try!` kullanmak isterdik. Ne yazık ki burada bu
mümkün değil, çünkü `Result` döndürmeyen `main` fonksiyonunun içindeyiz.

Her şey tamam! Hadi deneyelim! Sunucumuzu bir terminalde başlatıp ikinci bir
terminalde `dig` ile sorgulayalım.

```text
# dig @127.0.0.1 -p 2053 google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> @127.0.0.1 -p 2053 google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47200
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		68	IN	A	216.58.211.142

;; Query time: 1 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1)
;; WHEN: Fri Jul 08 12:07:44 CEST 2016
;; MSG SIZE  rcvd: 54
```

Sunucu terminalimize baktığımızda şunu görürüz:

```text
Received query: DnsQuestion { name: "google.com", qtype: A }
Answer: A { domain: "google.com", addr: 216.58.211.142, ttl: 96 }
```

Başardık! 800 satırdan az kodla, birkaç farklı kayıt türüyle sorgulara yanıt
verebilen bir DNS sunucusu kurduk!

Bir sonraki bölümde, mevcut bir resolver'a bağımlılığımızı ortadan kaldıracağız:
[Bölüm 5 - Recursive Resolve](chapter5.md)