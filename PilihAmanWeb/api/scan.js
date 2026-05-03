module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Metode tidak diizinkan' });
    }

    const { teks } = req.body;
    const GROQ_KEY = process.env.GROQ_API_KEY;
    const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

    try {
        let finalStatus = "AMAN";
        let pesanHasil = "";

        // 1. FILTER GOOGLE SAFE BROWSING (Otomatis Merah jika terdeteksi)
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
                finalStatus = "BAHAYA";
                pesanHasil = `<strong>Google Safe Browsing</strong> mendeteksi bahwa situs ini terdaftar sebagai Berbahaya/Phishing.`;
            }
        }

        // 2. FILTER GROQ AI
        if (finalStatus !== "BAHAYA") {
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
                            // INSTRUKSI BARU: Tambahkan status WASPADA
                            role: "system", 
                            content: "Kamu pakar siber. WAJIB balas HANYA dengan format: STATUS|Alasan. STATUS hanya boleh diisi 'BAHAYA', 'AMAN', atau 'WASPADA'." 
                        },
                        { role: "user", content: teks }
                    ],
                    temperature: 0.1
                })
            });
            
            if (!groqResponse.ok) throw new Error("Koneksi ke server AI Groq sedang terputus.");
            const data = await groqResponse.json();
            if (!data.choices || data.choices.length === 0) throw new Error("AI gagal memberikan respon.");

            const aiAnswer = data.choices[0].message.content;
            const parts = aiAnswer.split('|');
            const statusAI = parts[0].trim().toUpperCase();
            
            // LOGIKA PENENTUAN 3 WARNA
            if (statusAI.includes("BAHAYA")) {
                finalStatus = "BAHAYA";
            } else if (statusAI.includes("WASPADA") || statusAI.includes("HATI")) {
                finalStatus = "WASPADA";
            } else {
                finalStatus = "AMAN";
            }
            
            if (parts.length > 1) {
                pesanHasil = parts[1].trim();
            } else {
                pesanHasil = aiAnswer.replace(/BAHAYA|AMAN|WASPADA/gi, '').trim();
            }
        }

        // Kirim status yang baru ke Frontend
        return res.status(200).json({ status: finalStatus, pesanHasil });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
};
