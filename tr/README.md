# DNS Sunucusu İnşa Etmek

Bu klasör, İngilizce kaynak metnin Türkçe çalışma ağını içerir. Kök dizindeki İngilizce dosyalar referans olarak kalır; Türkçe sürüm bu klasörde ilerler.

## Başlangıç Rotası

1. Kaynak sürümün tamamı için önce [../README.md](../README.md) dosyasına bak.
2. Türkçe açıklamalar için bölüm sırasını bu ağaçta aynen izle.
3. Örneklerin Türkçe kopyalarını examples/ altında, İngilizce dosyalarla aynı adlarla bul.

## Neler Korunur

Çeviri yaparken hedefimiz yalnızca açıklama katmanını taşımak, davranışı değil.

* Kod blokları ve örnek çıktılar mümkün olduğunca korunur.
* Teknik terimler, bölüm sırası ve dosya eşleşmeleri sabit tutulur.
* Yeni çeviri, her zaman kaynak dosyayla karşılaştırılarak ilerler.

## Örnekler

Örnek kodların Türkçe açıklamaları ayrı bir alt ağaçta tutulur:

* `examples/` kökündeki İngilizce örnekler kaynak olarak kalır.
* `tr/examples/` altında aynı adlarla Türkçe yorumlu kopyalar bulunur.
* Yorumları çeviririz, kod satırlarını değiştirmeyiz.

## Bölümler

* [Bölüm 1 - DNS protokolü](chapter1.md)
* [Bölüm 2 - Bir stub resolver oluşturmak](chapter2.md)
* [Bölüm 3 - Daha fazla kayıt türü eklemek](chapter3.md)
* [Bölüm 4 - İlk DNS sunucumuz](chapter4.md)
* [Bölüm 5 - Recursive Resolve](chapter5.md)
