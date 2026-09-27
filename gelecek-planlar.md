# SecPlat — Ürün Yol Haritası ve Gelecek Planları (Product Roadmap)

SecPlat projesini açık kaynaklı ve kurumsal düzeyde bir **Uygulama Güvenliği ve Zafiyet Yönetimi Platformuna (Next-Gen DevSecOps & ASPM Platform)** dönüştürme planı.

---

## 1. Vizyon ve Konumlandırma

SecPlat; tekil güvenlik araçlarını (DAST, SAST, SCA, Secret Scanning, Recon) merkezi bir orkestrasyon motoru, birleşik bulgu havuzu ve otomatik aksiyon mekanizmaları ile bir araya getiren modern bir **ASPM (Application Security Posture Management)** platformudur.

---

## 2. Temel Modüller ve Yol Haritası

```
+-----------------------------------------------------------------------------------+
|                              SecPlat Web UI / Dashboard                           |
+-----------------------------------------------------------------------------------+
|  Recon (Subfinder) | DAST (Nuclei) | SAST (Semgrep) | SCA (Trivy) | Secrets (Gitleaks) |
+-----------------------------------------------------------------------------------+
|                             Orkestrasyon & Workflow Motoru                         |
+-----------------------------------------------------------------------------------+
|  Bulgu & Zafiyet Yönetimi (Triage, Dedup, Remediation, Jira/GitHub Sync)          |
+-----------------------------------------------------------------------------------+
|  CI/CD Entegrasyonu | API Gateway | Çoklu Organizasyon (RBAC) | Raporlama         |
+-----------------------------------------------------------------------------------+
```

---

### Faz 1: Tarama & Araç Genişletme (Tamamlanan & Yakın Plan)

- [x] **Nuclei**: Ağ & Web uygulaması zafiyet taraması (DAST).
- [x] **Subfinder**: Pasif subdomain keşfi ve saldırı yüzeyi tespiti (Recon).
- [x] **Semgrep**: Statik kaynak kod analizi ve kural tabanlı SAST.
- [x] **Trivy**: Konteyner, bağımlılık (SCA) ve IaC (Terraform, Dockerfile) zafiyet analizi.
- [x] **Gitleaks**: Git geçmişi ve yerel dizinler için gizli bilgi/anahtar (Secret Scanning) taraması.
- [x] **Checkov (IaC Security)**: Terraform, CloudFormation, Kubernetes, Dockerfile ve bulut altyapı güvenlik denetimi.
- [x] **HTTPx**: Aktif web servisi, teknoloji, HTTP durum kodu ve port keşif probu.
- [ ] **OWASP ZAP / Caido**: Aktif web fuzzer ve derin dinamik güvenlik testi entegrasyonu.

---

### Faz 2: Birleşik Tarama Profilleri & Workflow Motoru

Kullanıcının tek tek araç seçip çalıştırması yerine, belirli kullanım senaryolarına özel akışlar:

1. [x] **Full Codebase Audit & Birleşik Güvenlik Skoru**:
   - `Gitleaks` (Secret) $\rightarrow$ `Semgrep` (SAST) $\rightarrow$ `Trivy` (SCA/IaC) $\rightarrow$ `Checkov` (IaC) ardışık/orkestre çalışır.
   - Kod tabanı ve projeler için tek bir birleşik güvenlik skoru (0-100, A-F notlandırma) ve kategorik analiz üretir.
2. [x] **External Attack Surface Recon Pipeline**:
   - `Subfinder` (Subdomain Keşfi) $\rightarrow$ `HTTPx` (Aktif servis & teknoloji keşfi) $\rightarrow$ `Nuclei` (Hedefe yönelik DAST taraması).
3. **Zamanlanmış Taramalar (Scheduled Audits)**:
   - Proje bazında haftalık, günlük veya saatlik otomatik tarama kuralları tanımlama (Celery Beat altyapısı ile).

---

### Faz 3: Bulgu Yönetimi (Vulnerability Triage & Remediation)

- **Durum Makinesi**: Bulguları `open`, `in_review`, `false_positive`, `accepted_risk`, `resolved` olarak işaretleme.
- **SLA & Risk Takibi**: Kritik zafiyetler için çözüm süresi (MTTR) sayaçları.
- **İş Takip Entegrasyonları**:
  - Jira, GitHub Issues ve GitLab Issues üzerine tek tıkla bulgu aktarımı ve iki yönlü durum senkronizasyonu.
  - Slack / Microsoft Teams / Webhook ile kritik bulgu anlık bildirimleri.

---

### Faz 4: CI/CD Pipeline & Geliştirici Deneyimi

- **SecPlat CLI**: Terminalden veya CI/CD scriptlerinden (`secplat scan --target . --fail-on high`) tarama tetikleme.
- **GitHub Actions / GitLab CI Plugin**: Pull Request (PR) açıldığında diff taraması yapıp PR yorumu olarak bulguları basma.
- **Quality Gates**: Kritik zafiyet tespit edildiğinde deployment pipeline'ını durdurma (Break the Build).

---

### Faz 5: Kurumsal Özellikler (Enterprise & Scale)

- **RBAC & Çoklu Kiracılık (Multi-Tenancy)**: Organizasyon, takım ve kullanıcı yetkilendirmesi (Admin, SecOps, Developer, Viewer).
- **SSO / SAML / OIDC**: Google Workspace, Okta, Azure AD ile tek noktadan giriş.
- **Denetim Günlüğü (Audit Log)**: Hangi kullanıcının hangi taramayı başlattığı, hangi bulguyu kapattığına dair değiştirilemez log kayıtları.
- **Gelişmiş Uyumluluk Raporları (Compliance)**:
  - SOC2, ISO 27001, OWASP Top 10 ve PCI-DSS uyumluluk matrisi PDF dışa aktarımı.
