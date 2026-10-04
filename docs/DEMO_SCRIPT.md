# ScamLens: 2-minute hackathon demo script

**Before you start:** backend and Streamlit running, an AI API key set, and one fictional screenshot ready
(screenshot the "Bank impersonation" demo text, or any fictional scam chat).

| Time | Do | Say |
|---|---|---|
| 0:00 | Open ScamLens Home. | "Scams now arrive as bank alerts, job offers and 'Hi Mum' messages. People don't need a verdict, they need to know *why* something is risky and what to do." |
| 0:15 | **Message** tab. Pick *Bank impersonation* from the fictional examples, click **Analyze Message**. | "This message is fictional. Watch what comes back." |
| 0:30 | Point to the banner: CRITICAL RISK, level 4 of 4, AI Risk Confidence, category. | "Not just 'scam'. A level, a category, and a confidence score that is the AI's confidence, not a fraud probability." |
| 0:45 | Scroll the **Red flags**: urgency, OTP request, link. Show *Evidence* and *Why it matters*. | "Every flag quotes the message and explains it in plain language. We even check that the quote really appears in the message." |
| 1:00 | Show **Recommended actions**, **Verify before acting** and **Links**. | "Clear next steps. The link is analysed but never opened, and it isn't clickable." |
| 1:10 | Go Home and analyze the *Legitimate-looking notification* example. | "False positives matter. A real credit alert comes back LOW, and urgency alone can never push a message to HIGH." |
| 1:25 | **Screenshot** tab: upload the screenshot, click **Extract & review text**. Fix a word, click **Analyze this text**. | "OCR runs locally. The user reviews and corrects the text before anything goes to the AI." |
| 1:45 | Open **History**, then **Dashboard**. | "Everything is stored in SQLite: history you can reopen, and live statistics." |
| 1:55 | Close. | "ScamLens is decision support: recognise, understand the evidence, verify, then act. Explainable, with honest limits." |
