// phishing.js
class PhishingDetector {
    constructor() {
        this.spamWords = {};
        this.hamWords = {};
        this.spamCount = 0;
        this.hamCount = 0;
        this.totalWordsSpam = 0;
        this.totalWordsHam = 0;
    }

    extractFeatures(message, sender) {
        const lowerMessage = message.toLowerCase().trim();
        const words = lowerMessage.split(/\s+/).filter(w => w.length > 2);
        const senderDomain = sender.includes("@") ? sender.split("@")[1] : "unknown";
        const features = {};

        words.forEach(word => {
            features[word] = (features[word] || 0) + 1;
        });
        features["domain:" + senderDomain] = 1;

        const suspiciousSymbols = ["!", "!!", "...", "$", "@"];
        suspiciousSymbols.forEach(symbol => {
            const count = (lowerMessage.match(new RegExp(`\\${symbol}`, "g")) || []).length;
            if (count > 0) features["symbol:" + symbol] = count;
        });

        const linkPattern = /http[s]?:\/\/[^\s]+/i;
        features["hasLink"] = linkPattern.test(lowerMessage) ? 1 : 0;

        return features;
    }

    train(messages, labels) {
        messages.forEach((message, index) => {
            const sender = message.sender || "unknown@unknown";
            const features = this.extractFeatures(message.text, sender);
            const isSpam = labels[index] === 1;

            if (isSpam) {
                this.spamCount++;
                Object.keys(features).forEach(feature => {
                    this.spamWords[feature] = (this.spamWords[feature] || 0) + features[feature];
                    this.totalWordsSpam += features[feature];
                });
            } else {
                this.hamCount++;
                Object.keys(features).forEach(feature => {
                    this.hamWords[feature] = (this.hamWords[feature] || 0) + features[feature];
                    this.totalWordsHam += features[feature];
                });
            }
        });
    }

    predict(message, sender) {
        const features = this.extractFeatures(message, sender);
        const vocabSize = new Set([...Object.keys(this.spamWords), ...Object.keys(this.hamWords)]).size;

        const totalMessages = this.spamCount + this.hamCount;
        const spamPrior = this.spamCount / totalMessages;
        const hamPrior = this.hamCount / totalMessages;

        let spamLogProb = Math.log(spamPrior);
        let hamLogProb = Math.log(hamPrior);

        Object.keys(features).forEach(feature => {
            const spamFreq = this.spamWords[feature] || 0;
            const hamFreq = this.hamWords[feature] || 0;

            const spamProb = (spamFreq + 1) / (this.totalWordsSpam + vocabSize);
            const hamProb = (hamFreq + 1) / (this.totalWordsHam + vocabSize);

            spamLogProb += features[feature] * Math.log(spamProb);
            hamLogProb += features[feature] * Math.log(hamProb);
        });

        return spamLogProb > hamLogProb ? 1 : 0;
    }
}

const trainingData = [
    { text: "Срочно обнови пароль по ссылке http://fake.com", sender: "admin@gmail.com" },
    { text: "Ваш счет заблокирован! Перейдите http://bank.ru", sender: "support@yahoo.com" },
    { text: "Привет, как дела? Встретимся завтра?", sender: "friend@company.com" },
    { text: "Поздравляю с праздником!", sender: "team@work.org" }
];
const labels = [1, 1, 0, 0];

// Экспортируем, чтобы использовать в HTML
const detector = new PhishingDetector();
detector.train(trainingData, labels);

function checkPhishing() {
    const message = document.getElementById("message").value;
    const sender = document.getElementById("sender").value;
    if (!message || !sender) {
        document.getElementById("result").innerHTML = "Пожалуйста, заполните оба поля!";
        return;
    }
    const result = detector.predict(message, sender);
    document.getElementById("result").innerHTML = 
        result === 1 ? "⚠️ Фишинг" : "✅ Безопасно";
}