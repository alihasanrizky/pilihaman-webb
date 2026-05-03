module.exports = async function handler(req, res) {

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { teks } = req.body;

    const GROQ_KEY = process.env.GROQ_API_KEY;
    const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

    if (!GROQ_KEY || !GOOGLE_KEY) {
        return res.status(500).json({ error: "API key belum diset" });
    }

    try {
        let isBahaya = false;
        let pesanHasil = "";

        // ============================
        // 1. GOOGLE SAFE BROWSING (MULTI URL)
        // ============================
        const urls = teks.match(/https?:\/\/[^\s]+/g);

        if (urls) {
            for (const url of urls) {

                const googleRes = await fetch(
                    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
                    {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client: { clientId: "app", clientVersion: "1.0" },
                            threatInfo: {
                                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                                platformTypes: ["ANY_PLATFORM"],
                                threatEntryTypes: ["URL"],
                                threatEntries: [{ url }]
                            }
                        })
                    }
                );

                const gData = await googleRes.json();

                if (gData.matches) {
                    isBahaya = true;
                    pesanHasil = "Link terdeteksi berbahaya oleh Google";
                    break;
                }
            }
        }

        // ============================
        // 2. GROQ AI
        // ============================
        if (!isBahaya) {

            const groqRes = await fetch(
                'https://api.groq.com/openai/v1/chat/completions',
                {
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
                                content: "Balas format: BAHAYA|alasan atau AMAN|alasan"
                            },
                            { role: "user", content: teks }
                        ]
                    })
                }
            );

            if (!groqRes.ok) {
                throw new Error("AI error");
            }

            const data = await groqRes.json();

            const aiText = data?.choices?.[0]?.message?.content || "";

            if (!aiText.includes("|")) {
                throw new Error("Format AI tidak valid");
            }

            const [status, alasan] = aiText.split("|");

            isBahaya = status.toUpperCase().includes("BAHAYA");
            pesanHasil = alasan || "Tidak ada penjelasan";
        }

        return res.status(200).json({
            isBahaya,
            pesanHasil
        });

    } catch (err) {
        return res.status(500).json({
            error: err.message
        });
    }
};
