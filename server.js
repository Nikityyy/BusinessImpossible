const express = require('express');
const https = require('https');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const axios = require('axios');
var request = require("request");
const fetch = require('node-fetch');
const {
    RateLimiterMemory
} = require('rate-limiter-flexible');

const {
    Octokit
} = require('@octokit/core');


// SECURITY

// REMOVED :D

// SECURITY

const app = express();
const port = 3000;
const appIP = "localhost"

/*
const options = {
  key: fs.readFileSync(path.resolve(__dirname, 'certificate/_.business-impossible.tech_private_key.key')),
  cert: fs.readFileSync(path.resolve(__dirname, 'certificate/cbusiness-impossible.tech_ssl_certificate.cer')),
};
*/

app.use(bodyParser.json());
app.use(cors({
    origin: '*'
}));

//const server = https.createServer(options, app);

const maxGroupsLimit = 20;

const maxUsersPerGroup = 5;

const groupsFolderPath = path.join(__dirname, 'groups');

const githubToken = 'REMOVED';
const repoOwner = 'Nikityyy';
const repoName = 'REMOVED';
const filePath = 'users.txt';
const filePathW = 'users';
const filePathGroup = 'groups';

const octokit = new Octokit({
    auth: 'REMOVED',
});

/*
// ANTI DDOS by NIKITA ↓
const rateLimit = {
    windowMs: 10000,
    maxRequests: 20,
};

const requestCounts = new Map();

const rateLimiterMiddleware = (req, res, next) => {
    const ip = req.ip;
    const method = req.method;

    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, {});
    }

    const ipRequests = requestCounts.get(ip);

    if (!ipRequests[method]) {
        ipRequests[method] = {
            count: 0,
            lastReset: Date.now()
        };
    }

    const now = Date.now();

    if (now - ipRequests[method].lastReset > rateLimit.windowMs) {
        ipRequests[method].count = 0;
        ipRequests[method].lastReset = now;
    }

    if (ipRequests[method].count >= rateLimit.maxRequests) {
        console.log(`Rate limit exceeded for ${ip} (${method} request)`);

        const htmlContent = `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zu viele Anfragen</title>
    <link rel="icon" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAMAAAAKE/YAAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAACylBMVEUAAAAdHRulIzYdHRulIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzalIzb////LyOt9AAAA7HRSTlMAAAABAwsPDgYHKWCCmaKjn45sLwQrYo1rLkSe2vT8/vgZSPX3fxYBMZjn+pwCNeqWFQld0f32dl7UdHrr0CR7yyDxVvBNdXn5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">
    <style>
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #333;
        margin: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
        color: #fff;
      }

      main {
        background-color: #444;
        border-radius: 10px;
        box-shadow: 0 0 10px rgba(255, 255, 255, 0.1);
        overflow: hidden;
      }

      form {
        max-width: 320px;
        padding: 20px;
        box-sizing: border-box;
      }

      h2 {
        text-align: center;
        color: #fff;
        max-width: 280px;
      }

      p {
        text-align: center;
        margin-top: 15px;
        color: #bbb;
      }
    </style>
  </head>
  <body>
    <main>
	  <form>
		<h2>Zu viele Anfragen</h2>
		<p style="font-size: 20px"><b>Bitte lade die Website nicht zu oft neu oder stelle nicht zu viele Anfragen gleichzeitig.</b></p>
		<p><b>Nicht mehr als 20 Anfragen (Abruf oder Übermittlung von Daten) alle 10 Sekunden erlaubt.</b></p>
		<p>Bitte versuche es in 10 Sekunden erneut.</p>
	  </form>
    </main>
  </body>
</html>
    `;

        return res.status(429).send(htmlContent);
    }

    ipRequests[method].count += 1;

    console.log(`${ip} (${method} request) - Count: ${ipRequests[method].count}`);

    next();
};

app.use(rateLimiterMiddleware);
// ANTI DDOS by NIKITA ↑
*/

app.get('/users.txt', async (req, res) => {
    try {

        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: filePathW,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        });

        const fileNames = response.data.map(file => file.name.replace(/\.[^/.]+$/, ''));

        const formattedResponse = fileNames.join('\n');

        res.send(formattedResponse);
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: 'Fehler aufgetreten beim Extrahieren der Namen'
        });
    }
});

app.get('/groups.txt', async (req, res) => {
    try {

        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: filePathGroup,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        });

        const fileNames = response.data.map(file => file.name.replace(/\.[^/.]+$/, ''));

        const formattedResponse = fileNames.join('\n');

        res.send(formattedResponse);
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: 'Fehler aufgetreten beim Extrahieren der Namen'
        });
    }
});

async function hashPassword(password) {
    const saltRounds = 10;

    const salt = await bcrypt.genSalt(saltRounds);

    const hash = await bcrypt.hash(password, salt);

    return hash;
}

async function isUsernameTaken(username) {
    try {
        const response = await axios.get(`http://${appIP}:${port}/users.txt`, {
            responseType: 'text',
        });

        const userArray = response.data.trim().split('\n').map(entry => entry.split(':'));
        return userArray.some(([storedUsername]) => storedUsername === username);
    } catch (error) {
        console.error('Fehler beim Checken des Namens:', error);
        return true;
    }
}

app.post('/register', async (req, res) => {
    const {
        newUsername,
        newPassword
    } = req.body;

    try {
        if (!newUsername || !newPassword) {
            return res.status(400).json({
                success: false,
                error: 'Nutzername und Passwort sind benötigt'
            });
        }

        const isUsernameTaken = await isUsernameTakenOnGithub(newUsername);
        if (isUsernameTaken) {
            return res.status(400).json({
                success: false,
                error: 'Nutzername ist bereits vergeben'
            });
        }

        const hashedPassword = await encrypt(newPassword);
		
		console.log(newPassword);
		console.log(hashedPassword);

        if (!hashedPassword) {
            return res.status(500).json({
                success: false,
                error: 'Fehler beim Verschlüsseln des Passworts'
            });
        }

        let foundEmail = null;

        const [nachname, vorname] = newUsername.split('.');

        const hakSteyrDatenbankURL = `http://${appIP}:${port}/HAK-Steyr-Datenbank`;
        const hakSteyrDatenbankResponse = await axios.get(hakSteyrDatenbankURL);
        const hakSteyrEmails = hakSteyrDatenbankResponse.data.split('\n');

        console.log(`Checking for ${newUsername} in HAK-Steyr-Datenbank`);

        const exactMatchEmail = hakSteyrEmails.find(email => {
            const [emailNachname, emailVorname] = email.toLowerCase().split('@')[0].split('.');
            return (emailNachname === nachname.toLowerCase() && emailVorname === vorname.toLowerCase()) ||
                (emailNachname === vorname.toLowerCase() && emailVorname === nachname.toLowerCase());
        });

        const startsWithMail = hakSteyrEmails.filter(email => {
            const [emailNachname, emailVorname] = email.toLowerCase().split('@')[0].split('.');
            return (emailNachname.startsWith(nachname.toLowerCase()) && emailVorname.startsWith(vorname.toLowerCase())) ||
                (emailNachname.startsWith(vorname.toLowerCase()) && emailVorname.startsWith(nachname.toLowerCase()));
        });

        if (exactMatchEmail) {
            foundEmail = [exactMatchEmail];
            console.log(`${newUsername} found in HAK-Steyr-Datenbank: ${exactMatchEmail}`);
        } else if (startsWithMail) {
            if (startsWithMail.length > 0) {
                startsWithMail.forEach(matchingEmail => {
                    console.log(matchingEmail);
                });
                foundEmail = startsWithMail;
            } else {
                console.log(`Failed: ${newUsername} not found in HAK-Steyr-Datenbank`);
            }
        } else {
            const bothIncludedEmails = hakSteyrEmails.filter(email => {
                const [emailNachname, emailVorname] = email.toLowerCase().split('@')[0].split('.');
                return (emailNachname.includes(nachname.toLowerCase()) && emailVorname.includes(vorname.toLowerCase())) ||
                    (emailNachname.includes(vorname.toLowerCase()) && emailVorname.includes(nachname.toLowerCase()));
            });

            if (bothIncludedEmails.length > 0) {
                console.log(`Both Vorname and Nachname included in ${newUsername}:`);
                bothIncludedEmails.forEach(matchingEmail => {
                    console.log(matchingEmail);
                });
                foundEmail = bothIncludedEmails;
            } else {
                console.log(`Failed: ${newUsername} not found in HAK-Steyr-Datenbank`);
            }
        }

        let emailList = Array.isArray(foundEmail) ? (foundEmail.length === 1 ? 'Mögliche Email:' : 'Mögliche Emails:') + '\n' + foundEmail.join('\n') : 'Keine Email gefunden';

        const filePath = `users/${newUsername}.txt`;

        const commitMessage = `Add user ${newUsername}`;

        const createFileData = {
            owner: repoOwner,
            repo: repoName,
            path: filePath,
            message: commitMessage,
		content: Buffer.from(`${newUsername}:${hashedPassword}\n\n${emailList}`).toString('base64'),
        };

        const createFileResponse = await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', createFileData);

        if (createFileResponse.status !== 200 && createFileResponse.status !== 201) {
            return res.status(500).json({
                success: false,
                error: `Fehler beim Erstellen der Datei: ${createFileResponse.statusText}`
            });
        }

        res.json({
            success: true
        });
    } catch (error) {
        console.error('Fehler während der Registrierung:', error);
        res.status(500).json({
            success: false,
            error: 'Interner Server Fehler'
        });
    }
});

async function isUsernameTakenOnGithub(username) {
    try {
        const filePath = `users/${username}.txt`;

        const existingFileResponse = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: filePath,
        });

        return existingFileResponse.status === 200;
    } catch (error) {
        return false;
    }
}

async function getSecurityURL(secureURL) {
    return new Promise((resolve, reject) => {
        request({
            url: secureURL,
            followRedirect: false
        }, (error, response, body) => {
            if (error) {
                console.error('Fehler:', error);
                reject(error);
            } else {
                if (response.statusCode >= 300 && response.statusCode < 400) {
                    const securedURL = response.headers.location;
                    resolve(securedURL);
                } else {
                    resolve(secureURL);
                }
            }
        });
    });
}

app.post('/login', async (req, res) => {
    const {
        username,
        password
    } = req.body;

    try {
        const storedPasswordHash = await getPasswordHash(username);

        if (!storedPasswordHash) {
            res.json({
                success: false,
                error: 'Falsche Anmeldeinformationen'
            });
            return;
        }

        const startTrimIndex = username.length + 1;
		const newlineIndex = storedPasswordHash.indexOf('\n', startTrimIndex);


		if (newlineIndex !== -1) {
		const trimmedPassword = storedPasswordHash.slice(startTrimIndex, newlineIndex);
        const checkPassword = trimmedPassword.trim();

        const passwordMatch = await bcrypt.compare(password, checkPassword);
		
		const disgustMatch = await decrypt(password, checkPassword);

        if (passwordMatch) {
            res.json({
                success: true
            });
        } else if (disgustMatch) {
            res.json({
                success: true
            });
        } else {
            console.error(`Falsches Passwort für ${username}`);
            res.json({
                success: false,
                error: 'Falsche Anmeldeinformationen'
            });
        }
		}
    } catch (error) {
        console.error('Fehler beim Einloggen:', error);
        res.status(500).json({
            success: false,
            error: 'Interer Server Fehler'
        });
    }
});

async function getPasswordHash(username) {
    try {
        const filePath = `users/${username}.txt`;
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: filePath,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        });

        if (response.status !== 200) {
            console.error(`User ${username} does not exist`);
            return null;
        }

        const storedPasswordHash = response.data.content;

        const decodedPasswordHash = Buffer.from(storedPasswordHash, 'base64').toString('utf-8');

        return decodedPasswordHash;
    } catch (error) {
        console.error('Fehler beim Erhalten des Passworts von der Datenbank:', error);
        return null;
    }
}


async function getGroupList() {
    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: filePathGroup,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        });

        const data = response.data;

        if (!Array.isArray(data) || data.length === 0) {
            return [];
        }

        const groupArray = data.map(file => path.basename(file.name, '.txt'));
        return groupArray;
    } catch (error) {
        console.error('Fehler beim Erhalten der Gruppenliste:', error);
        return [];
    }
}


app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/defaultsite', (req, res) => {
    const filePath = path.join(__dirname, 'login.html');

    res.sendFile(filePath);
});

app.get('/login', (req, res) => {
    const filePath = path.join(__dirname, 'login.html');

    res.sendFile(filePath);
});

app.get('/Datenschutz', (req, res) => {
    const filePath = path.join(__dirname, 'datenschutz.html');

    res.sendFile(filePath);
});

app.get('/Impressum', (req, res) => {
    const filePath = path.join(__dirname, 'impressum.html');

    res.sendFile(filePath);
});

app.get('/Partner', (req, res) => {
    const filePath = path.join(__dirname, 'partner.html');

    res.sendFile(filePath);
});

app.get('/HAK-Steyr-Datenbank', (req, res) => {
    const filePath = path.join(__dirname, 'HAK-Steyr-Datenbank.txt');

    res.sendFile(filePath);
});

app.get('/Impossible', (req, res) => {
    const filePath = path.join(__dirname, 'index.html');

    res.sendFile(filePath);
});

app.get('/profile/:username', (req, res) => {
    const filePath = path.join(__dirname, 'profile.html');

    res.sendFile(filePath);
});

app.post('/createGroup', async (req, res) => {
    const {
        groupName,
        creator
    } = req.body;

    try {

        const filePath = `groups/${groupName}.txt`;

        const commitMessage = `Gruppe hinzugefügt ${groupName}`;

        const createFileData = {
            owner: repoOwner,
            repo: repoName,
            path: filePath,
            message: commitMessage,
            content: Buffer.from(creator).toString('base64'),
        };

        const createFileResponse = await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', createFileData);

        if (createFileResponse.status !== 200 && createFileResponse.status !== 201) {
            return res.status(500).json({
                success: false,
                error: `Fehler beim Erstellen der Datei: ${createFileResponse.statusText}`
            });
        }

        res.json({
            success: true
        });
    } catch (error) {
        console.error('Fehler während der Registrierung:', error);
        res.status(500).json({
            success: false,
            error: 'Interner Server Fehler'
        });
    }
});

app.post('/joinGroup', async (req, res) => {
    const {
        groupName,
        username
    } = req.body;
    const groupFilePath = `groups/${groupName}.txt`;

    try {
        let response;
        try {
            response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
                owner: repoOwner,
                repo: repoName,
                path: groupFilePath,
            });
        } catch (error) {
            if (error.status === 404) {
                const initialContent = username;
                await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
                    owner: repoOwner,
                    repo: repoName,
                    path: groupFilePath,
                    message: 'Gruppe erstellen',
                    committer: {
                        name: 'Nikity',
                        email: 'REMOVED',
                    },
                    content: Buffer.from(initialContent).toString('base64'),
                });

                res.json({
                    success: true
                });
                return;
            } else {
                throw error;
            }
        }

        const existingContent = Buffer.from(response.data.content, 'base64').toString('utf-8');
        const groupList = existingContent.trim().split('\n').map(entry => entry.trim());

        const userGroups = await getUserGroups(username, groupFilePath);

        if (!groupList.includes(username)) {
            if (userGroups.includes(groupName)) {
                console.error(`Nutzer ${username} ist bereits Mitglied der Gruppe ${groupName}`);
                res.json({
                    success: false,
                    error: 'Bereits ein Mitglied der Gruppe'
                });
                return;
            }

            if (userGroups.length >= maxUsersPerGroup) {
                console.error(`Maximales Limit von ${maxUsersPerGroup} Nutzern erreicht in der Gruppe ${groupName}`);
                res.json({
                    success: false,
                    error: `Maximales Limit von ${maxUsersPerGroup} Nutzern erreicht`
                });
                return;
            }

            const groupCreator = await getGroupCreator(groupFilePath);
            if (groupCreator === username) {
                console.error(`Nutzer ${username} ist bereits in der Gruppe`);
                res.json({
                    success: false,
                    error: 'Bereits in der Gruppe'
                });
                return;
            }

            const newContent = groupList.concat(username).join('\n');

            await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
                owner: repoOwner,
                repo: repoName,
                path: groupFilePath,
                message: 'Aktualisiere Gruppenmitglieder',
                committer: {
                    name: 'Nikity',
                    email: 'REMOVED',
                },
                content: Buffer.from(newContent).toString('base64'),
                sha: response.data.sha,
            });

            res.json({
                success: true
            });
        } else {
            console.error(`Nutzer ${username} ist bereits Mitglied der Gruppe ${groupName}`);
            res.json({
                success: false,
                error: 'Bereits ein Mitglied der Gruppe'
            });
        }
    } catch (error) {
        console.error('Fehler beim Beitreten der Gruppe:', error);
        res.status(500).json({
            success: false,
            error: 'Interner Server Fehler'
        });
    }
});

async function getGroupCreator(groupFilePath) {
    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: groupFilePath,
        });

        const content = Buffer.from(response.data.content, 'base64').toString('utf-8');
        const membersArray = content.trim().split('\n').map(entry => entry.trim());

        return membersArray.length > 0 ? membersArray[0] : null;
    } catch (error) {
        console.error(`Fehler beim Erhalten des Gruppenerstellers von der Datei ${groupFilePath}:`, error.message);
        return null;
    }
}


app.get('/getGroupMembers/:groupName', async (req, res) => {
    const groupName = req.params.groupName;
    const groupFilePath = `groups/${groupName}.txt`;

    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: groupFilePath,
        });

        const content = Buffer.from(response.data.content, 'base64').toString('utf-8');
        const membersArray = content.trim().split('\n').map(entry => entry.trim());

        res.json({
            creator: membersArray[0],
            members: membersArray.slice(1)
        });
    } catch (error) {
        console.error(`Fehler beim Erhalten der Gruppenmitglieder von ${groupName} von der Datenbank:`, error);
        res.status(500).json({
            creator: null,
            members: []
        });
    }
});

async function leaveGroupAndUpdate(username, groupFilePath, groupName) {
    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: groupFilePath,
        });

        const content = Buffer.from(response.data.content, 'base64').toString('utf-8');
        const membersArray = content.trim().split('\n').map(entry => entry.trim());

        const updatedMembers = membersArray.filter(member => member !== username);

        await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: groupFilePath,
            message: `Nutzer ${username} hat die Gruppe verlassen`,
            committer: {
                name: 'Nikity',
                email: 'REMOVED',
            },
            content: Buffer.from(updatedMembers.join('\n')).toString('base64'),
            sha: response.data.sha,
        });

        if (updatedMembers.length === 0) {
            const latestResponse = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
                owner: repoOwner,
                repo: repoName,
                path: groupFilePath,
            });

            await octokit.request('DELETE /repos/{owner}/{repo}/contents/{path}', {
                owner: repoOwner,
                repo: repoName,
                path: groupFilePath,
                message: `Lösche Gruppe ${groupName}`,
                committer: {
                    name: 'Nikity',
                    email: 'REMOVED',
                },
                sha: latestResponse.data.sha,
            });
        } else if (membersArray[0] === username) {
            const newCreator = membersArray[Math.floor(Math.random() * (updatedMembers.length - 1)) + 1];
            await setGroupCreator(groupFilePath, newCreator);
        }

        return {
            success: true
        };
    } catch (error) {
        console.error('Fehler beim Verlassen der Gruppe:', error);
        return {
            success: false,
            error: 'Interner Server Fehler'
        };
    }
}

app.post('/leaveGroup', async (req, res) => {
    const {
        groupName,
        username
    } = req.body;
    const groupFilePath = `groups/${groupName}.txt`;

    const result = await leaveGroupAndUpdate(username, groupFilePath, groupName);
    res.json(result);
});

app.get('/getAllUsers', async (req, res) => {
    try {
        const response = await axios.get(`http://${appIP}:${port}/users.txt`, {
            responseType: 'text',
        });

        const userArray = response.data.trim().split('\n').map(entry => entry.split(':'));

        const users = userArray.map(([username]) => username);

        res.json({
            users
        });
    } catch (error) {
        console.error('Fehler beim Erhalten aller Nutzer:', error);
        res.status(500).json({
            users: []
        });
    }
});

app.post('/deleteGroup', async (req, res) => {
    const {
        groupName,
        username
    } = req.body;
    const groupFilePath = `groups/${groupName}.txt`;

    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: groupFilePath,
        });

        const groupCreator = await getGroupCreator(groupFilePath);

        if (groupCreator === username) {
            await octokit.request('DELETE /repos/{owner}/{repo}/contents/{path}', {
                owner: repoOwner,
                repo: repoName,
                path: groupFilePath,
                message: 'Lösche Gruppe',
                committer: {
                    name: 'Nikity',
                    email: 'REMOVED',
                },
                sha: response.data.sha,
            });

            res.json({
                success: true
            });
        } else {
            res.json({
                success: false,
                error: 'Nur der Ersteller kann die Gruppe löschen'
            });
        }
    } catch (error) {
        if (error.status === 404) {
            res.json({
                success: false,
                error: 'Die Gruppe existiert nicht'
            });
        } else {
            console.error('Fehler beim Löschen der Gruppe:', error);
            res.status(500).json({
                success: false,
                error: 'Interner Server Fehler'
            });
        }
    }
});

app.get('/getGroups', async (req, res) => {
    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: filePathGroup,
            headers: {
                'X-GitHub-Api-Version': '2022-11-28'
            }
        });

        const fileNames = response.data.map(file => file.name.replace(/\.[^/.]+$/, ''));
        const formattedResponse = fileNames.join('\n');

        const groupArray = fileNames.map(fileName => path.basename(fileName, '.txt'));

        res.json({
            groups: groupArray
        });
    } catch (error) {
        if (error.status === 404) {
            res.json({
                groups: []
            });
        } else {
            console.error('Fehler beim Erhalten aller Gruppen:', error);

            res.status(500).json({
                groups: []
            });
        }
    }
});

async function getUserGroups(username, groupFilePath) {
    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
            owner: repoOwner,
            repo: repoName,
            path: groupFilePath,
        });

        const content = Buffer.from(response.data.content, 'base64').toString('utf-8');
        return content.trim().split('\n').map(entry => entry.trim());
    } catch (error) {
        console.error('Fehler beim Erhalten der Nutzergruppen:', error);
        return [];
    }
}

// HTTP:
app.listen(port, () => {
    console.log(`Server läuft auf http://${appIP}:${port}`);
});

// HTTPS:
// server.listen(port, () => {
  // console.log(`Server listening on port ${port}`);
// });