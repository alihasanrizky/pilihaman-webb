export default async function handler(req, res) {
    // Hanya izinkan perintah POST
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Metode tidak diizinkan' });
    }

    const { teks } = req.body;
    
    // Vercel akan membaca kunci rahasia ini dari dashboard mereka
    // Kunci ini TIDAK AKAN PERNAH sampai ke browser pengguna
    const GROQ_KEY = process.env.GROQ_API_KEY;
    const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

    try {
        let isBahaya = false;
        let pesanHasil = "";

        // 1. CEK GOOGLE SAFE BROWSING
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
                pesanHasil = `<strong>Google Safe Browsing</strong> mendeteksi situs ini Berbahaya/Phishing.`;
            }
        }

        // 2. CEK GROQ AI
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
                        { role: "system", content: "Kamu pakar siber. Balas format: 'STATUS|Alasan singkat'. Jika bahaya STATUS='BAHAYA', jika aman STATUS='AMAN'." },
                        { role: "user", content: teks }
                    ],
                    temperature: 0.2
                })
            });
            
            const data = await groqResponse.json();
            const aiAnswer = data.choices[0].message.content;
            const parts = aiAnswer.split('|');
            isBahaya = parts[0].trim().toUpperCase().includes("BAHAYA");
            pesanHasil = parts.length > 1 ? parts[1].trim() : aiAnswer;
        }

        // Kirim hasil akhir kembali ke index.html
        return res.status(200).json({ isBahaya, pesanHasil });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
}