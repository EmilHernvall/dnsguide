Bölüm 5 - Recursive Resolve
===========================

Sunucumuz çalışıyor; ancak aramayı gerçekten yapmak için başka bir sunucuya
bağımlı olmak hem can sıkıcı hem de pek kullanışlı değil. Şimdi bir adın aslında
nasıl çözümlendiğinin ayrıntılarına inmek için iyi bir zamandayız.

Önceden hiçbir bilgi bilinmediğini varsayarsak, sorgu ilk olarak internetin 13
kök sunucusundan birine gönderilir. Neden 13? Çünkü 512 baytlık bir DNS paketine
ancak o kadar sığar (daha doğrusu 14 için yer vardır ama biraz pay bırakılmıştır).
13 sayısı tüm interneti idare etmek için biraz düşük gibi görünebilir ve haklı
olursunuz -- 13 mantıksal sunucu vardır, ancak gerçekte çok daha fazlası bulunur.
Bunun hakkında daha fazlasını [burada](http://www.root-servers.org/) okuyabilirsiniz.
Her resolver, bu 13 sunucuyu önceden bilmek zorundadır. Hepsini bind biçiminde
içeren bir dosya mevcuttur ve [named.root](https://www.internic.net/domain/named.root)
olarak adlandırılır. Bu sunucuların hepsi aynı bilgiyi içerir; bu yüzden başlamak
için onlardan birini rastgele seçebiliriz. `named.root`'a baktığımızda,
*a.root-servers.net* için IP adresinin 198.41.0.4 olduğunu görürüz; bu yüzden
ilk sorgumuzda bunu kullanacağız: *www.google.com*.

```text
# dig +norecurse @198.41.0.4 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @198.41.0.4 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64866
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 16

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.google.com.			IN	A

;; AUTHORITY SECTION:
com.			172800	IN	NS	e.gtld-servers.net.
com.			172800	IN	NS	b.gtld-servers.net.
com.			172800	IN	NS	j.gtld-servers.net.
com.			172800	IN	NS	m.gtld-servers.net.
com.			172800	IN	NS	i.gtld-servers.net.
com.			172800	IN	NS	f.gtld-servers.net.
com.			172800	IN	NS	a.gtld-servers.net.
com.			172800	IN	NS	g.gtld-servers.net.
com.			172800	IN	NS	h.gtld-servers.net.
com.			172800	IN	NS	l.gtld-servers.net.
com.			172800	IN	NS	k.gtld-servers.net.
com.			172800	IN	NS	c.gtld-servers.net.
com.			172800	IN	NS	d.gtld-servers.net.

;; ADDITIONAL SECTION:
e.gtld-servers.net.	172800	IN	A	192.12.94.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
m.gtld-servers.net.	172800	IN	A	192.55.83.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30

;; Query time: 24 msec
;; SERVER: 198.41.0.4#53(198.41.0.4)
;; WHEN: Fri Jul 08 14:09:20 CEST 2016
;; MSG SIZE  rcvd: 531
```

Kök sunucular *www.google.com* hakkında bilgi sahibi değildir, ancak *com*
hakkında bilgi sahibidir; bu yüzden yanıt bize sırada nereye gitmemiz gerektiğini
söyler. Burada dikkat edilmesi gereken birkaç şey var:

 * Yetki bölümünde yer alan bir dizi NS kaydı verilir. NS kayıtları bize bir
   alan adını yöneten ad sunucusunun *adını* söyler.
 * Sunucu, NS kayıtlarına karşılık gelen A kayıtlarını da ekleyerek yardımcı
   olur; böylece ikinci bir sorgu yapmamıza gerek kalmaz.
 * Aslında *com* için değil, *www.google.com* için sorgu yaptık. Ancak NS
   kayıtlarının hepsi *com* ile ilgilidir.

Sonuçtan bir sunucu seçip devam edelim. *a.gtld-servers.net* için `192.5.6.30`
gayet uygun görünüyor.

```text
# dig +norecurse @192.5.6.30 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @192.5.6.30 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16229
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.google.com.			IN	A

;; AUTHORITY SECTION:
google.com.		172800	IN	NS	ns2.google.com.
google.com.		172800	IN	NS	ns1.google.com.
google.com.		172800	IN	NS	ns3.google.com.
google.com.		172800	IN	NS	ns4.google.com.

;; ADDITIONAL SECTION:
ns2.google.com.		172800	IN	A	216.239.34.10
ns1.google.com.		172800	IN	A	216.239.32.10
ns3.google.com.		172800	IN	A	216.239.36.10
ns4.google.com.		172800	IN	A	216.239.38.10

;; Query time: 114 msec
;; SERVER: 192.5.6.30#53(192.5.6.30)
;; WHEN: Fri Jul 08 14:13:26 CEST 2016
;; MSG SIZE  rcvd: 179
```

Hâlâ *www.google.com* noktasında değiliz, ama en azından artık *google.com*
alanını yöneten sunucuların bir kümesine sahibiz. Sorgumuzu bu kez
*216.239.32.10* adresine göndererek tekrar deneyelim.

```text
# dig +norecurse @216.239.32.10 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +norecurse @216.239.32.10 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20432
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.com.			IN	A

;; ANSWER SECTION:
www.google.com.		300	IN	A	216.58.211.132

;; Query time: 10 msec
;; SERVER: 216.239.32.10#53(216.239.32.10)
;; WHEN: Fri Jul 08 14:15:11 CEST 2016
;; MSG SIZE  rcvd: 48
```

İşte karşımızda! İstediğimiz *www.google.com* IP adresi. Özetleyelim:

 * *a.root-servers.net* bize *a.gtld-servers.net*'i kontrol etmemizi söyler;
   bu sunucu com'u yönetir
 * *a.gtld-servers.net* bize *ns1.google.com*'u kontrol etmemizi söyler;
   bu sunucu google.com'u yönetir
 * *ns1.google.com* bize *www.google.com*'un IP adresini söyler

Bu oldukça tipik bir durumdur ve önbellek olmadan bile çoğu sorgu en fazla üç
adım gerektirir. Yine de alt alan adları için ad sunucuları ve onların da alt
alan adları için daha derin sunucular olması mümkündür. Pratikte bir DNS
sunucusu bir önbellek tutar ve çoğu TLD zaten önceden bilinir. Bu da çoğu
sorgunun sunucu tarafından yalnızca iki, yaygın olarak da bir ya da sıfır
arama gerektireceği anlamına gelir.

### Recursive aramalar için DnsPacket'i genişletmek

Devam etmeden önce `DnsPacket` üzerinde birkaç yardımcı işleve ihtiyacımız var.

```rust
impl DnsPacket {

	- snip -

	/// Bir paketten rastgele bir A kaydı seçebilmek kullanışlıdır. Bir ad için
	/// birden fazla IP aldığımızda hangisini seçeceğimiz önemli değildir;
	/// dolayısıyla bu durumlarda rastgele birini seçebiliriz.
	pub fn get_random_a(&self) -> Option<Ipv4Addr> {
		self.answers
			.iter()
			.filter_map(|record| match record {
				DnsRecord::A { addr, .. } => Some(*addr),
				_ => None,
			})
			.next()
	}

	/// Yetkiler bölümündeki tüm ad sunucuları üzerinde bir yineleyici döndüren
	/// yardımcı işlev; (domain, host) demetleri olarak temsil edilir.
	fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
		self.authorities
			.iter()
			// Uygulamada bunlar düzgün biçimlendirilmiş paketlerde her zaman NS
			// kayıtlarıdır. NS kayıtlarını yalnızca ihtiyaç duyduğumuz veriye
			// sahip bir demete dönüştürerek kullanımı kolaylaştırırız.
			.filter_map(|record| match record {
				DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
				_ => None,
			})
			// Sorgumuza yetkili olmayan sunucuları ele
			.filter(move |(domain, _)| qname.ends_with(*domain))
	}

	/// Ad sunucularının NS sorgularına yanıt verirken ilgili A kayıtlarını da
	/// sık sık birlikte göndermesi gerçeğini kullanarak, mümkünse bir NS kaydı
	/// için gerçek IP'yi döndüren bir işlev uygulayacağız.
	pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
		// Yetkiler bölümündeki ad sunucuları üzerinde bir yineleyici al
		self.get_ns(qname)
			// Şimdi ek bölümde eşleşen bir A kaydı aramamız gerekiyor. İlk
			// geçerli kaydı istiyoruz, bu yüzden eşleşen kayıtların akışını
			// oluşturabiliriz.
			.flat_map(|(_, host)| {
				self.resources
					.iter()
					// Şu anda işlediğimiz NS kaydının host alanıyla eşleşen
					// alan adına sahip A kayıtlarını filtrele
					.filter_map(move |record| match record {
						DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
						_ => None,
					})
			})
			.map(|addr| *addr)
			// Son olarak ilk geçerli girdiyi seç
			.next()
	}

	/// Ancak her ad sunucusu bu kadar cömert değildir. Bazı durumlarda,
	/// ek bölümde hiçbir A kaydı bulunmaz ve o sırada *başka bir* sorgu daha
	/// yapmak zorunda kalırız. Bunun için, uygun bir ad sunucusunun host adını
	/// döndüren bir yöntem ekliyoruz.
	pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
		// Yetkiler bölümündeki ad sunucuları üzerinde bir yineleyici al
		self.get_ns(qname)
			.map(|(_, host)| host)
			// Son olarak ilk geçerli girdiyi seç
			.next()
	}

} // End of DnsPacket
```

### Recursive aramayı uygulamak

Yeni `recursive_lookup` fonksiyonumuza hızla geçiyoruz:

```rust
fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
	// Şimdilik hep *a.root-servers.net* ile başlıyoruz.
	let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

	// Keyfi sayıda adım gerekebileceği için sınırsız bir döngüye giriyoruz.
	loop {
		println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

		// Sıradaki adım sorguyu aktif sunucuya göndermek.
		let ns_copy = ns;

		let server = (ns_copy, 53);
		let response = lookup(qname, qtype, server)?;

		// Yanıt bölümünde girişler varsa ve hata yoksa, işimiz bitti!
		if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
			return Ok(response);
		}

		// Yetkili sunucuların adın var olmadığını bize söyleme yolu olan
		// `NXDOMAIN` yanıtını da alabiliriz.
		if response.header.rescode == ResultCode::NXDOMAIN {
			return Ok(response);
		}

		// Aksi durumda, ek bölümdeki uygun bir NS ve onun A kaydına göre yeni
		// bir ad sunucusu bulmaya çalışacağız. Başarılı olursa, ad sunucusunu
		// değiştirip döngüyü tekrar deneriz.
		if let Some(new_ns) = response.get_resolved_ns(qname) {
			ns = new_ns;

			continue;
		}

		// Bu da olmazsa, bir NS kaydının IP'sini çözmemiz gerekir. Eğer NS kaydı
		// yoksa, son sunucunun bize söylediğiyle yetiniriz.
		let new_ns_name = match response.get_unresolved_ns(qname) {
			Some(x) => x,
			None => return Ok(response),
		};

		// Burada, mevcut arama akışımızın içinde başka bir çözümleme dizisi
		// başlatarak tavşan deliğinin derinliklerine iniyoruz. Umarız bu bize
		// uygun bir ad sunucusunun IP'sini verir.
		let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

		// Son olarak sonuçtan rastgele bir IP seçip döngüyü yeniden başlatıyoruz.
		// Eğer böyle bir kayıt yoksa, yine son aldığımız sonucu döndürürüz.
		if let Some(new_ns) = recursive_response.get_random_a() {
			ns = new_ns;
		} else {
			return Ok(response);
		}
	}
}
```

Bu aynı zamanda `lookup` fonksiyonunda küçük bir değişiklik gerektirir; çünkü
hangi sunucunun kullanılacağını parametre olarak almamız gerekir. Fonksiyon
imzasına bir sunucu parametresi ekleyip, 4. bölümde kullandığımız sabit `server`
değişkenini kaldırıyoruz:

```rust
fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
```

### Recursive aramayı denemek

Geriye kalan tek şey `handle_query` fonksiyonumuzu `recursive_lookup`
kullanacak şekilde değiştirmek:

```rust
fn handle_query(socket: &UdpSocket) -> Result<()> {

	- snip -

			println!("Received query: {:?}", question);
			if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
				packet.questions.push(question.clone());
				packet.header.rescode = result.header.rescode;

	- snip -

}
```

Hadi deneyelim!

```text
# dig @127.0.0.1 -p 2053 www.google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> @127.0.0.1 -p 2053 www.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41892
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.com.			IN	A

;; ANSWER SECTION:
www.google.com.		300	IN	A	216.58.211.132

;; Query time: 76 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1)
;; WHEN: Fri Jul 08 14:31:39 CEST 2016
;; MSG SIZE  rcvd: 62
```

Sunucu penceremize baktığımızda şunu görürüz:

```text
Received query: DnsQuestion { name: "www.google.com", qtype: A }
attempting lookup of A www.google.com with ns 198.41.0.4
attempting lookup of A www.google.com with ns 192.12.94.30
attempting lookup of A www.google.com with ns 216.239.34.10
Answer: A { domain: "www.google.com", addr: 216.58.211.132, ttl: 300 }
```

Bu, biraz önceki manuel sürecimizi yansıtıyor. Artık kök sunucular listesinden
başlayarak bir alan adını başarıyla çözebiliyoruz. Böylece tamamen işlevsel,
fakat mükemmel olmayan bir DNS sunucumuz oldu.

Daha iyi yapabileceğimiz pek çok şey var. Örneğin, bu sunucuda gerçek bir
eşzamanlılık yok. TCP üzerinden ne sorgu gönderebiliyoruz ne de alabiliyoruz.
Kendi zone'larımızı barındırmak için kullanamıyoruz ve onu yetkili bir sunucu
olarak çalıştıramıyoruz. DNSSEC desteğinin olmaması bizi DNS zehirleme
saldırılarına açık bırakıyor; kötü niyetli bir sunucu başkasının alan adıyla
ilgili kayıtları geri döndürebilir.

Bu sorunların birçoğu kendi projem [hermes](https://github.com/EmilHernvall/hermes)
içinde giderildi; istersen oraya gidip bunu nasıl yaptığımı inceleyebilir veya
buradan kendi yolunuza devam edebilirsiniz. Ya da belki artık DNS'ten yeterince
yararlanmışsınızdır... :) Her durumda, DNS'in nasıl çalıştığına dair yeni bir
bakış açısı kazandığınızı umuyorum.