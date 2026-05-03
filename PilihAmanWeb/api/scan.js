module.exports = async function handler(req, res) {
    // Hanya izinkan metode POST
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Metode tidak diizinkan' });
    }

    const { teks } = req.body;
    
    // Mengambil kunci rahasia dari brankas Vercel (Environment Variables)
    const GROQ_KEY = process.env.GROQ_API_KEY;
    const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

    try {
        let isBahaya = false;
        let pesanHasil = "";

        // ==========================================
        // 1. FILTER LAPIS PERTAMA: GOOGLE SAFE BROWSING
        // ==========================================
        const tautanDitemukan = teks.match(/https?:\/\/[^\s]+/g);
        if (tautanDitemukan && tautanDitemukan.length > 0) {
            const urlYangDicek = tautanDitemukan[0];
            const googleResponse = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: { clientId: "pilihaman-web", clientVersion: "1.0" },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: urlYangDicek }]
                    }
                })
            });
            
            const googleData = await googleResponse.json();
            if (googleData.matches && googleData.matches.length > 0) {
                isBahaya = true;
                pesanHasil = `<strong>Google Safe Browsing</strong> mendeteksi bahwa situs ini terdaftar sebagai Berbahaya/Phishing.`;
            }
        }

        // ==========================================
        // 2. FILTER LAPIS KEDUA: GROQ AI (LLAMA 3.1)
        // ==========================================
        if (!isBahaya) {
            const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${GROQ_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: "llama-3.1-8b-instant",
                    messages: [
                        { 
                            role: "system", 
                            content: "Kamu pakar siber. WAJIB balas HANYA dengan format: STATUS|Alasan. STATUS hanya boleh diisi kata 'BAHAYA' atau 'AMAN'." 
                        },
                        { 
                            role: "user", 
                            content: teks 
                        }
                    ],
                    temperature: 0.1
                })
            });
            
            // Validasi apakah koneksi ke Groq berhasil
            if (!groqResponse.ok) {
                throw new Error("Koneksi ke server AI Groq sedang terputus.");
            }

            const data = await groqResponse.json();
            
            if (!data.choices || data.choices.length === 0) {
                 throw new Error("AI gagal memberikan respon.");
            }

            const aiAnswer = data.choices[0].message.content;
            
            // Membedah jawaban AI dengan sangat presisi
            const parts = aiAnswer.split('|');
            const status = parts[0].trim().toUpperCase();
            
            if (status.includes("BAHAYA")) {
                isBahaya = true;
            } else {
                isBahaya = false;
            }
            
            // Membersihkan teks sebelum ditampilkan
            if (parts.length > 1) {
                pesanHasil = parts[1].trim();
            } else {
                pesanHasil = aiAnswer.replace(/BAHAYA|AMAN/gi, '').trim();
            }
        }

        // Mengirim data akhir kembali ke Frontend (index.html)
        return res.status(200).json({ isBahaya, pesanHasil });

    } catch (error) {
        // Tangkap semua error dan kirimkan dalam format JSON agar Frontend tidak tersedak HTML
        return res.status(500).json({ error: error.message });
    }
};
