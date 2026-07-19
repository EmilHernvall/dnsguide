Bölüm 1 - DNS protokolü
=======================

DNS protokolünü inceleyerek başlayacak ve bu bilgimizi basit bir istemci
uygulamak için kullanacağız.

Geleneksel olarak DNS paketleri UDP üzerinden gönderilir ve 512 bayt ile
sınırlıdır. Daha sonra göreceğimiz gibi, bu iki kuralın da istisnaları vardır:
DNS TCP üzerinden de kullanılabilir ve eDNS adı verilen bir mekanizma ile paket
boyutunu genişletebiliriz. Şimdilik, yine de özgün belirtimi esas alacağız.

DNS'in kullanışlı tarafı, sorgu ve yanıtların aynı biçimi kullanmasıdır. Bu da
bir paket ayrıştırıcı ve bir paket yazıcı yazdığımız anda protokol kısmını
tamamlamış olacağımız anlamına gelir. Bu, genellikle farklı istek ve yanıt
yapıları kullanan çoğu internet protokolünden ayrılır. Yüksek seviyede bir DNS
paketi şu şekilde görünür:

| Bölüm             | Boyut    | Tür               | Amaç                                                                                                   |
| ----------------- | -------- | ----------------- | ------------------------------------------------------------------------------------------------------ |
| Başlık            | 12 Bayt  | Başlık            | Sorgu/yanıt hakkında bilgi.                                                                            |
| Soru Bölümü       | Değişken | Soru Listesi      | Uygulamada yalnızca sorgu adını (alan adı) ve ilgilenilen kayıt türünü belirten tek bir soru vardır.   |
| Yanıt Bölümü      | Değişken | Kayıt Listesi     | İstenen türdeki ilgili kayıtlar.                                                                       |
| Yetki Bölümü      | Değişken | Kayıt Listesi     | Sorguları özyinelemeli çözmekte kullanılan ad sunucuları (NS kayıtları) listesi.                       |
| Ek Bölüm          | Değişken | Kayıt Listesi     | Örneğin NS kayıtları için karşılık gelen A kayıtları gibi yararlı olabilecek ek kayıtlar.             |

Temelde, üç farklı nesneyi desteklememiz gerekir: Başlık, Soru ve Kayıt.
Neyse ki, kayıt ve soru listeleri herhangi bir ek olmadan, sadece art arda
eklenmiş ayrı örneklerden oluşur. Her bölümdeki kayıt sayısı başlık tarafından
verilir. Başlık yapısı şu şekildedir:

| RFC Adı | Açıklayıcı Ad       | Uzunluk            | Açıklama                                                                                                                                                                         |
| ------- | ------------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID      | Paket Tanımlayıcısı | 16 bit             | Sorgu paketlerine rastgele bir tanımlayıcı atanır. Yanıt paketleri aynı kimlikle cevap vermelidir. Bu, UDP'nin durumsuz yapısı nedeniyle yanıtları ayırt etmek için gereklidir. |
| QR      | Sorgu/Yanıt        | 1 bit              | Sorgular için 0, yanıtlar için 1.                                                                                                                                                |
| OPCODE  | İşlem Kodu         | 4 bit              | Genellikle her zaman 0'dır; ayrıntılar için RFC1035'e bakın.                                                                                                                     |
| AA      | Otoriter Yanıt     | 1 bit              | Yanıt veren sunucu otoriter ise, yani sorgulanan alan adının sahibi ise 1 yapılır.                                                                                               |
| TC      | Kısaltılmış İleti  | 1 bit              | İleti uzunluğu 512 baytı aşarsa 1 yapılır. Geleneksel olarak sorgunun TCP ile yeniden gönderilebileceğine dair bir işaret kabul edilir; çünkü TCP'de bu sınır yoktur.           |
| RD      | Özyineleme İsteği  | 1 bit              | Sunucunun, hazır bir yanıt yoksa sorguyu özyinelemeli çözmeyi denemesini isteyen istemci tarafından ayarlanır.                                                                    |
| RA      | Özyineleme Uygun   | 1 bit              | Sunucu tarafından, özyinelemeli sorgulara izin verilip verilmediğini belirtmek için ayarlanır.                                                                                  |
| Z       | Ayrılmış           | 3 bit              | Başlangıçta daha sonra kullanılmak üzere ayrılmıştı, ancak artık DNSSEC sorgularında kullanılıyor.                                                                               |
| RCODE   | Yanıt Kodu         | 4 bit              | Sunucu tarafından yanıtın durumunu belirtmek için ayarlanır; yani başarılı mı başarısız mı olduğunu ve başarısızsa nedenini belirtir.                                           |
| QDCOUNT | Soru Sayısı        | 16 bit             | Soru Bölümündeki giriş sayısı                                                                                                                                                    |
| ANCOUNT | Yanıt Sayısı       | 16 bit             | Yanıt Bölümündeki giriş sayısı                                                                                                                                                    |
| NSCOUNT | Yetki Sayısı       | 16 bit             | Yetki Bölümündeki giriş sayısı                                                                                                                                                    |
| ARCOUNT | Ek Sayı            | 16 bit             | Ek Bölümdeki giriş sayısı                                                                                                                                                        |

Soru kısmı biraz daha az korkutucudur:

| Alan   | Tür            | Açıklama                                                           |
| ------ | -------------- | ------------------------------------------------------------------ |
| Name   | Etiket Dizisi  | Aşağıda açıklandığı gibi etiket dizisi olarak kodlanan alan adı.   |
| Type   | 2 baytlık tamsayı | Kayıt türü.                                                      |
| Class  | 2 baytlık tamsayı | Sınıf; pratikte her zaman 1 olarak ayarlanır.                    |

Alan adının kodlanışındaki asıl zor kısım daha sonra geri döneceğimiz bir
konudur.

Son olarak, protokolün asıl gövdesini oluşturan kayıtlarımız var. Birçok kayıt
türü vardır, ancak şimdilik yalnızca birkaç temel türü ele alacağız. Tüm
kayıtların aşağıdaki ön bölümü vardır:

| Alan   | Tür            | Açıklama                                                                      |
| ------ | -------------- | ----------------------------------------------------------------------------- |
| Name   | Etiket Dizisi  | Aşağıda açıklandığı gibi etiket dizisi olarak kodlanan alan adı.              |
| Type   | 2 baytlık tamsayı | Kayıt türü.                                                                 |
| Class  | 2 baytlık tamsayı | Sınıf; pratikte her zaman 1 olarak ayarlanır.                              |
| TTL    | 4 baytlık tamsayı | Yaşam süresi; yani bir kaydın önbelleğe alınmadan önce ne kadar tutulacağı. |
| Len    | 2 baytlık tamsayı | Kayıt türüne özgü verinin uzunluğu.                                          |

Şimdi belirli kayıt türlerine bakmaya hazırız ve en temelinden başlayacağız:
bir adı bir IP'ye eşleyen A kaydı.

| Alan      | Tür             | Açıklama                                                                     |
| --------- | --------------- | ---------------------------------------------------------------------------- |
| Ön bölüm  | Kayıt Ön Bölümü | Yukarıda açıklanan kayıt ön bölümü; uzunluk alanı 4 olarak ayarlanmıştır.    |
| IP        | 4 baytlık tamsayı | Dört baytlık tamsayı olarak kodlanmış bir IP adresi.                      |

Buraya kadar geldikten sonra, bunu pratikte görmek için `dig` aracıyla bir
arama yapalım:

```text
# dig +noedns google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +noedns google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36383
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             204     IN      A       172.217.18.142

;; Query time: 0 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Wed Jul 06 13:24:19 CEST 2016
;; MSG SIZE  rcvd: 44
```

Özgün biçimde kaldığımızdan emin olmak için `+noedns` bayrağını kullanıyoruz.
Yukarıdaki çıktıda dikkat çeken birkaç nokta var:

 * `dig` aracının yanıt paketinin başlık, soru ve yanıt bölümlerini açıkça
   anlattığını görebiliriz.
 * Başlıkta OPCODE QUERY kullanılıyor; bu da 0'a karşılık gelir. Durum
   (RESCODE) NOERROR olarak ayarlanmıştır; bu da sayısal olarak 0'dır. Kimlik
   36383'tür ve yinelenen sorgularda rastgele değişecektir. Sorgu/Yanıt (qr),
   Özyineleme İsteği (rd), Özyineleme Uygun (ra) bayrakları etkin durumdadır;
   bunlar sayısal olarak 1'dir. DNSSEC ile ilgili olduğu için şimdilik `ad`
   bayrağını göz ardı edebiliriz. Son olarak başlık bize bir soru ve bir yanıt
   kaydı olduğunu söyler.
 * Soru bölümü, `IN` ile sınıfı ve A ile A kayıtları için sorgu yaptığımızı
   gösteren isteğimizi sunar.
 * Yanıt bölümü, google'ın IP adresiyle birlikte yanıt kaydını içerir. `204`
   TTL'dir, IN yine sınıfı, A ise kayıt türünü gösterir. Son olarak google.com
   IP adresine sahibiz.
 * Son satır, toplam paket boyutunun 44 bayt olduğunu söyler.

Bununla birlikte hâlâ görünmeyen bazı ayrıntılar var; bu yüzden daha da derine
inip paketlerin bir hexdump'ına bakalım. Bir portu dinlemek için `netcat` kullanabilir,
ardından `dig` aracını sorguyu oraya gönderecek şekilde yönlendirebiliriz. Bir
terminal penceresinde şunu çalıştırırız:

```text
# nc -u -l 1053 > query_packet.txt
```

Sonra başka bir pencerede şunu yaparız:

```text
# dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com

; <<>> DiG 9.10.3-P4-Ubuntu <<>> +retry=0 -p 1053 @127.0.0.1 +noedns google.com
; (1 server found)
;; global options: +cmd
;; connection timed out; no servers could be reached
```

Bu durumda başarısızlık beklenir; çünkü `dig`, bir yanıt almadığında zaman
aşımına uğrar. Bu başarısızlıkla birlikte süreç sona erer. Bu noktada `netcat`
Ctrl+C ile kapatılabilir. Elimizde `query_packet.txt` içinde bir sorgu paketi
kalır. Bu sorgu paketini bir yanıt paketi kaydetmek için de kullanabiliriz:

```text
# nc -u 8.8.8.8 53 < query_packet.txt > response_packet.txt
```

Biraz bekleyip Ctrl+C ile iptal edelim. Artık paketlerimizi incelemeye hazırız:

```text
# hexdump -C query_packet.txt
00000000  86 2a 01 20 00 01 00 00  00 00 00 00 06 67 6f 6f  |.*. .........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01              |gle.com.....|
0000001c
# hexdump -C response_packet.txt
00000000  86 2a 81 80 00 01 00 01  00 00 00 00 06 67 6f 6f  |.*...........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01 c0 0c 00 01  |gle.com.........|
00000020  00 01 00 00 01 25 00 04  d8 3a d3 8e              |.....%...:..|
0000002c
```

Bunun birazını anlamlandırmaya çalışalım. Daha önce öğrendiğimiz gibi, başlık
12 bayt uzunluğundadır. Sorgu paketi için başlık baytları şunlardır:
`86 2a 01 20 00 01 00 00 00 00 00 00` Son sekiz baytın farklı bölümlerin
uzunluğunu temsil ettiğini görebiliriz; gerçek içerik barındıran tek kısım, tek
bir giriş içeren soru bölümüdür. En ilginç kısım, başlığın farklı alanlarına
karşılık gelen ilk dört bayttır. Öncelikle, hem sorguda hem yanıt için aynı
kalması gereken 2 baytlık bir kimliğimiz olduğunu biliyoruz. Nitekim bu örnekte
her iki hexdump'ta da `86 2a` olarak ayarlanmış durumda. Ayrıştırılması zor olan
kısım kalan iki bayttır. Bunları anlamak için ikili biçime çevirmemiz gerekir.
Sorgu paketindeki `01 20` ile başlayalım; en anlamlı bit soldan başlayarak
şunu elde ederiz:

```text
0 0 0 0 0 0 0 1  0 0 1 0 0 0 0 0
-+-+-+-+- - - -  - -+-+- -+-+-+-
Q    O    A T R  R   Z      R
R    P    A C D  A          C
	 C                      O
	 O                      D
	 D                      E
```

DNSSEC ile ilgili `Z` bölümündeki bit hariç, bu beklediğimiz gibi. `QR` bir
sorgu olduğu için 0'dır, `OPCODE` da standart bir arama olduğu için 0'dır,
`AA`, `TC` ve `RA` bayrakları sorgular için önemli değildir; buna karşılık `RD`
etkindir, çünkü `dig` varsayılan olarak özyinelemeli çözüm istemektedir. Son
olarak `RCODE` de sorgular için kullanılmaz.

Yanıt paketinin bayrakları olan `81 80` kısmına geçelim:

```text
1 0 0 0 0 0 0 1  1 0 0 0 0 0 0 0
-+-+-+-+- - - -  - -+-+- -+-+-+-
Q    O    A T R  R   Z      R
R    P    A C D  A          C
	 C                      O
	 O                      D
	 D                      E
	 E
```

Bu bir yanıt olduğu için `QR` ayarlanmıştır ve sunucunun özyinelemeyi
desteklediğini belirtmek için `RA` da ayarlanmıştır. Geriye kalan sekiz bayta
bakınca, tek bir soruya ek olarak tek bir yanıt kaydı olduğunu görürüz.

Başlığın hemen ardından soru gelir. Bunu bayt bayt ayıralım:

```text
					query name              type   class
	   -----------------------------------  -----  -----
HEX    06 67 6f 6f 67 6c 65 03 63 6f 6d 00  00 01  00 01
ASCII     g  o  o  g  l  e     c  o  m
DEC    6                    3           0       1      1
```

Önceki tabloda belirtildiği gibi, bu üç parçadan oluşur: sorgu adı, tür ve
sınıf. Adın nasıl kodlandığında ilginç bir ayrıntı vardır; ortada nokta yoktur.
Bunun yerine DNS her adı, her etiketi uzunluğunu belirten tek bir baytın
önde olduğu bir `etiketler` dizisi olarak kodlar. Yukarıdaki örnekte "google"
6 bayttır ve bu yüzden önünde `0x06` vardır; "com" ise 3 bayttır ve önünde
`0x03` bulunur. Son olarak, tüm adlar sıfır uzunluklu bir etiketle, yani bir
null baytla sonlandırılır. Kolay görünüyor değil mi? Pekâlâ, biraz sonra başka
bir dönüş olduğunu göreceğiz.

Şimdi sorgu paketimizin sonuna geldik, ancak yanıt paketinde çözülecek biraz
veri kaldı. Geri kalan veri, google.com için karşılık gelen IP adresini taşıyan
tek bir A kaydıdır:

```text
	  name     type   class         ttl        len      ip
	  ------  ------  ------  --------------  ------  --------------
HEX   c0  0c  00  01  00  01  00  00  01  25  00  04  d8  3a  d3  8e
DEC   192 12    1       1           293         4     216 58  211 142
```

Bunun çoğu beklediğimiz gibidir: Type A kayıt için 1'dir, Class IN için 1'dir,
TTL bu durumda makul görünen 293'tür, veri uzunluğu olması gerektiği gibi 4'tür
ve sonunda google'ın IP'sinin `216.58.211.142` olduğunu öğreniriz. Peki ad
alanında ne oluyor? Az önce öğrendiğimiz etiketler nerede?

DNS'in orijinal 512 baytlık paket boyutu sınırı nedeniyle, bir tür sıkıştırma
gerekiyordu. Alan adları için gereken alanın çoğu isimlerden oluştuğundan ve
aynı adın bir kısmı tekrar tekrar ortaya çıkma eğiliminde olduğundan, burada
açık bir alan tasarrufu fırsatı vardır. Örneğin şu DNS sorgusunu düşünün:

```text
# dig @a.root-servers.net com

- snip -

;; AUTHORITY SECTION:
com.                172800  IN  NS      e.gtld-servers.net.
com.                172800  IN  NS      b.gtld-servers.net.
com.                172800  IN  NS      j.gtld-servers.net.
com.                172800  IN  NS      m.gtld-servers.net.
com.                172800  IN  NS      i.gtld-servers.net.
com.                172800  IN  NS      f.gtld-servers.net.
com.                172800  IN  NS      a.gtld-servers.net.
com.                172800  IN  NS      g.gtld-servers.net.
com.                172800  IN  NS      h.gtld-servers.net.
com.                172800  IN  NS      l.gtld-servers.net.
com.                172800  IN  NS      k.gtld-servers.net.
com.                172800  IN  NS      c.gtld-servers.net.
com.                172800  IN  NS      d.gtld-servers.net.

;; ADDITIONAL SECTION:
e.gtld-servers.net. 172800  IN  A       192.12.94.30
b.gtld-servers.net. 172800  IN  A       192.33.14.30
b.gtld-servers.net. 172800  IN  AAAA    2001:503:231d::2:30
j.gtld-servers.net. 172800  IN  A       192.48.79.30
m.gtld-servers.net. 172800  IN  A       192.55.83.30
i.gtld-servers.net. 172800  IN  A       192.43.172.30
f.gtld-servers.net. 172800  IN  A       192.35.51.30
a.gtld-servers.net. 172800  IN  A       192.5.6.30
a.gtld-servers.net. 172800  IN  AAAA    2001:503:a83e::2:30
g.gtld-servers.net. 172800  IN  A       192.42.93.30
h.gtld-servers.net. 172800  IN  A       192.54.112.30
l.gtld-servers.net. 172800  IN  A       192.41.162.30
k.gtld-servers.net. 172800  IN  A       192.52.178.30
c.gtld-servers.net. 172800  IN  A       192.26.92.30
d.gtld-servers.net. 172800  IN  A       192.31.80.30

- snip -
```

Burada internet kök sunucularından birine, .com üst düzey alan adını yöneten ad
sunucuları için sorgu yapıyoruz. `gtld-servers.net.` ifadesinin tekrar tekrar
karşımıza çıktığına dikkat edin; onu yalnızca bir kez eklemek daha kullanışlı
olmaz mıydı? Bunu sağlamanın bir yolu, paket ayrıştırıcısına başka bir konuma
atlamasını ve adı oradan okumayı bitirmesini söyleyen bir "atlama yönergesi"
eklemektir. Görünüşe göre yanıt paketimizde tam olarak buna bakıyoruz.

Az önce her etiketin önünde tek baytlık bir uzunluk bulunduğunu söylemiştim.
Burada dikkate almamız gereken ek ayrıntı şu: Eğer uzunluk baytının en anlamlı
iki biti ayarlıysa, bunun ardından ikinci bir bayt bekleyebiliriz. Bu iki bayt
birlikte ve en anlamlı iki biti çıkarılmış halde, atlama konumunu belirtir.
Yukarıdaki örnekte `0xC00C` değerine sahibiz. İki üst bitin hex olarak ifade
edilmiş hali `0xC000`'dir (ikilikte `11000000 00000000`), bu yüzden bu baytları
bu maskeyle XOR'layarak bu bitleri sıfırlayıp atlama konumunu bulabiliriz:
`0xC00C ^ 0xC000 = 12`. Dolayısıyla paket içinde 12. bayta atlamalı ve oradan
okumaya başlamalıyız. DNS başlığının 12 bayt olduğunu hatırlarsak, bunun bizi
paketin soru kısmının başladığı yere yönlendirdiğini fark ederiz; bu da mantıklı
çünkü soru, bu durumda "google.com" olan sorgu alan adıyla başlar. Adı okumayı
bitirdikten sonra ayrıştırmaya kaldığımız yerden devam eder ve kayıt türüne
ilerleriz.

### BytePacketBuffer

Artık uygulamaya başlamak için yeterince şey biliyoruz! İlk iş olarak paketleri
manipüle etmek için kullanışlı bir yönteme ihtiyacımız var. Bunun için
`BytePacketBuffer` adlı bir `struct` kullanacağız.

```rust
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
```

### ResultCode

Başlığa geçmeden önce, `rescode` alanının değerleri için bir enum ekleyeceğiz:

```rust
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
```

### DnsHeader

Şimdi başlık üzerinde çalışmaya başlayabiliriz. Onu şu şekilde temsil edeceğiz:

```rust
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
```

Uygulama, oldukça fazla bit düzeyi oynama içeriyor:

```rust
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

		Ok(())
	}
}
```

### QueryType

Sıradaki paket kısmına geçmeden önce, sorgulanan kayıt türünü temsil edecek bir
yolumuz olması gerekir:

```rust
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
```

### DnsQuestion

Bu enum, ileride daha fazla kayıt türü eklememizi kolaylaştırır. Şimdi soru
girişlerine gelelim:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
	pub name: String,
	pub qtype: QueryType,
}

impl DnsQuestion {
	pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
		DnsQuestion {
			name: name,
			qtype: qtype,
		}
	}

	pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
		buffer.read_qname(&mut self.name)?;
		self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
		let _ = buffer.read_u16()?; // class

		Ok(())
	}
}
```

Alan adlarını `BytePacketBuffer` yapımızın parçası olarak okumanın zor kısmını
çözdükten sonra, bunun oldukça kompakt olduğu ortaya çıkıyor.

### DnsRecord

Gerçek dns kayıtlarını da temsil edecek bir yapıya ihtiyacımız olacak; yine
kolay genişletme için bir enum kullanacağız:

```rust
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
```

Birçok kayıt türü olduğundan, henüz karşılaşmadığımız kayıt türlerini de takip
edebilme yeteneği ekleyeceğiz. Bu enum, ileride kolayca yeni kayıtlar
eklememizi de sağlar. `DnsRecord`'un gerçek uygulaması şöyle görünür:

```rust
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

				Ok(DnsRecord::A {
					domain: domain,
					addr: addr,
					ttl: ttl,
				})
			}
			QueryType::UNKNOWN(_) => {
				buffer.step(data_len as usize)?;

				Ok(DnsRecord::UNKNOWN {
					domain: domain,
					qtype: qtype_num,
					data_len: data_len,
					ttl: ttl,
				})
			}
		}
	}
}
```

### DnsPacket

Son olarak, bunların hepsini `DnsPacket` adlı bir yapıda birleştirelim:

```rust
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
```

### Hepsini Bir Araya Getirmek

Biraz önce oluşturduğumuz `response_packet.txt` dosyasını kullanıp bunu test
edelim!

```rust
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
```

Çalıştırdığımızda şu çıktıyı alırız:

```text
DnsHeader {
	id: 34346,
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
	addr: 216.58.211.142,
	ttl: 293
}
```

Bir sonraki bölümde ağ bağlantısını ekleyeceğiz: [Bölüm 2 - Bir stub resolver oluşturmak](chapter2.md)