/**
 * sentinel.js - Interactive Client Controller for Sentinel AI Workspace
 */

let currentConversationId = null;
let currentProvider = "mock";

document.addEventListener("DOMContentLoaded", () => {
    loadConversations();
    loadProviderConfig();
    setupEventListeners();
});

function setupEventListeners() {
    const chatInput = document.getElementById("chatInput");
    const sendBtn = document.getElementById("sendBtn");
    const newChatBtn = document.getElementById("newChatBtn");
    const providerSelect = document.getElementById("providerSelect");
    const openByokBtn = document.getElementById("openByokBtn");
    const killSwitchBtn = document.getElementById("killSwitchBtn");

    sendBtn.addEventListener("click", () => sendMessage());
    chatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    newChatBtn.addEventListener("click", () => startNewConversation());

    providerSelect.addEventListener("change", (e) => {
        currentProvider = e.target.value;
        document.getElementById("activeModelTag").textContent = `Modèle: ${e.target.options[e.target.selectedIndex].text}`;
        updateActiveProvider(currentProvider);
    });

    openByokBtn.addEventListener("click", (e) => {
        e.preventDefault();
        openByokModal();
    });

    killSwitchBtn.addEventListener("click", () => toggleKillSwitch());
}

async function loadConversations() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/conversations");
        const data = await res.json();
        const container = document.getElementById("conversationsContainer");
        container.innerHTML = "";

        if (!data.conversations || data.conversations.length === 0) {
            container.innerHTML = `<div style="color: #64748b; font-size: 0.75rem; text-align: center; padding: 1rem;">Aucun historique récent</div>`;
            return;
        }

        data.conversations.forEach((conv, index) => {
            const item = document.createElement("div");
            item.className = `conv-item ${conv.id === currentConversationId ? 'active' : ''}`;
            item.innerHTML = `
                <span class="conv-title"><i class="fa-regular fa-message" style="margin-right: 6px;"></i> ${escapeHtml(conv.title)}</span>
                <button onclick="deleteConv(event, '${conv.id}')" style="background: none; border: none; color: #64748b; cursor: pointer;">
                    <i class="fa-solid fa-trash-can"></i>
                </button>
            `;
            item.addEventListener("click", () => switchConversation(conv.id, conv.title));
            container.appendChild(item);

            if (index === 0 && !currentConversationId) {
                switchConversation(conv.id, conv.title);
            }
        });
    } catch (e) {
        console.error("Erreur chargement conversations", e);
    }
}

async function startNewConversation() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/conversations", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({title: "Nouvelle session d'audit"})
        });
        const data = await res.json();
        if (data.success) {
            currentConversationId = data.conversation_id;
            document.getElementById("chatTitle").textContent = "Nouvelle session d'audit";
            clearChatStream();
            loadConversations();
        }
    } catch (e) {
        console.error("Erreur création conversation", e);
    }
}

async function switchConversation(convId, title) {
    currentConversationId = convId;
    document.getElementById("chatTitle").textContent = title || "Session d'audit";
    document.querySelectorAll(".conv-item").forEach(el => el.classList.remove("active"));

    try {
        const res = await fetch(`/__sc/security/api/sentinel/conversations/${convId}`);
        const data = await res.json();
        const stream = document.getElementById("chatStream");
        stream.innerHTML = "";

        if (data.messages && data.messages.length > 0) {
            data.messages.forEach(msg => {
                appendMessageToUI(msg.role, msg.content, msg.tool_results);
            });
        }
        scrollChatToBottom();
    } catch (e) {
        console.error("Erreur chargement messages", e);
    }
}

async function deleteConv(e, convId) {
    e.stopPropagation();
    if (!confirm("Voulez-vous supprimer cette session d'audit ?")) return;

    try {
        await fetch(`/__sc/security/api/sentinel/conversations/${convId}`, { method: "DELETE" });
        if (currentConversationId === convId) {
            currentConversationId = null;
            clearChatStream();
        }
        loadConversations();
    } catch (err) {
        console.error("Erreur suppression", err);
    }
}

async function sendMessage() {
    const input = document.getElementById("chatInput");
    const text = input.value.trim();
    if (!text) return;

    input.value = "";
    appendMessageToUI("user", text);
    scrollChatToBottom();

    // Loading indicator
    const stream = document.getElementById("chatStream");
    const loaderId = "loader_" + Date.now();
    const loaderEl = document.createElement("div");
    loaderEl.id = loaderId;
    loaderEl.className = "msg-bubble msg-assistant";
    loaderEl.innerHTML = `
        <div class="avatar avatar-sentinel"><i class="fa-solid fa-spinner fa-spin"></i></div>
        <div class="msg-content" style="color: #94a3b8; font-style: italic;">
            Sentinel AI analyse la requête et coordonne les outils sous contrôle du Guardian...
        </div>
    `;
    stream.appendChild(loaderEl);
    scrollChatToBottom();

    try {
        const res = await fetch("/__sc/security/api/sentinel/chat", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                message: text,
                conversation_id: currentConversationId,
                provider: currentProvider
            })
        });

        const data = await res.json();
        const loader = document.getElementById(loaderId);
        if (loader) loader.remove();

        if (data.error) {
            appendMessageToUI("assistant", `⚠️ Erreur : ${data.error}`);
        } else {
            if (data.conversation_id && !currentConversationId) {
                currentConversationId = data.conversation_id;
                loadConversations();
            }
            appendMessageToUI("assistant", data.reply, data.tools_executed);
        }
        scrollChatToBottom();
    } catch (e) {
        const loader = document.getElementById(loaderId);
        if (loader) loader.remove();
        appendMessageToUI("assistant", `⚠️ Erreur réseau : Impossible de contacter Sentinel AI (${e.message})`);
        scrollChatToBottom();
    }
}

function sendQuickPrompt(promptText) {
    const input = document.getElementById("chatInput");
    input.value = promptText;
    sendMessage();
}

function appendMessageToUI(role, content, toolsExecuted = []) {
    const stream = document.getElementById("chatStream");
    const bubble = document.createElement("div");
    bubble.className = `msg-bubble msg-${role === 'user' ? 'user' : 'assistant'}`;

    const avatarHtml = role === 'user' 
        ? `<div class="avatar avatar-user"><i class="fa-solid fa-user"></i></div>`
        : `<div class="avatar avatar-sentinel"><i class="fa-solid fa-shield-halved"></i></div>`;

    let toolsHtml = "";
    if (toolsExecuted && toolsExecuted.length > 0) {
        toolsExecuted.forEach(t => {
            const hasFindings = t.result && t.result.findings && t.result.findings.length > 0;
            const badgeColor = hasFindings ? "#ef4444" : "#10b981";
            const badgeText = hasFindings ? `${t.result.findings.length} vulnérabilité(s) identifiée(s)` : "Vérification conforme";

            toolsHtml += `
                <div class="tool-card">
                    <div class="tool-header">
                        <span><i class="fa-solid fa-screwdriver-wrench"></i> ${escapeHtml(t.name)}</span>
                        <span style="color: ${badgeColor}; font-size: 0.72rem; font-weight: 600;">${badgeText}</span>
                    </div>
                    <div class="tool-details">
                        <strong>Paramètres:</strong> ${escapeHtml(JSON.stringify(t.arguments))}<br>
                        ${hasFindings ? `<div style="margin-top: 6px; color: #f87171;"><strong>Preuves techniques:</strong> ${escapeHtml(JSON.stringify(t.result.findings))}</div>` : ''}
                    </div>
                </div>
            `;
        });
    }

    bubble.innerHTML = `
        ${avatarHtml}
        <div class="msg-content">
            ${toolsHtml}
            <div>${formatMarkdown(content)}</div>
        </div>
    `;

    stream.appendChild(bubble);
}

function formatMarkdown(text) {
    if (!text) return "";
    let html = escapeHtml(text);
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    html = html.replace(/`([^`]+)`/g, '<code style="background: rgba(0,0,0,0.3); padding: 2px 5px; border-radius: 4px; font-family: monospace;">$1</code>');
    html = html.replace(/\n\n/g, '<br><br>');
    html = html.replace(/\n/g, '<br>');
    return html;
}

function escapeHtml(text) {
    if (!text) return "";
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

function scrollChatToBottom() {
    const stream = document.getElementById("chatStream");
    stream.scrollTop = stream.scrollHeight;
}

function clearChatStream() {
    const stream = document.getElementById("chatStream");
    stream.innerHTML = `
        <div class="msg-bubble msg-assistant">
            <div class="avatar avatar-sentinel"><i class="fa-solid fa-robot"></i></div>
            <div class="msg-content">
                <p style="margin-top:0;">Nouvelle session démarrée. Quelle vérification de sécurité souhaitez-vous effectuer ?</p>
            </div>
        </div>
    `;
}

async function loadProviderConfig() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/config");
        const data = await res.json();
        currentProvider = data.active_provider || "mock";
        const select = document.getElementById("providerSelect");
        select.value = currentProvider;
        document.getElementById("activeModelTag").textContent = `Modèle: ${select.options[select.selectedIndex].text}`;

        if (data.kill_switch) {
            updateKillSwitchUI(true);
        }
    } catch (e) {
        console.error("Erreur chargement config BYOK", e);
    }
}

async function updateActiveProvider(providerId) {
    try {
        await fetch("/__sc/security/api/sentinel/config", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ active_provider: providerId })
        });
    } catch (e) {
        console.error("Erreur màj provider", e);
    }
}

function openByokModal() {
    document.getElementById("byokModal").classList.add("active");
}

function closeByokModal() {
    document.getElementById("byokModal").classList.remove("active");
}

async function saveByokConfig() {
    const pId = document.getElementById("modalProviderSelect").value;
    const apiKey = document.getElementById("modalApiKey").value;
    const model = document.getElementById("modalModel").value;
    const baseUrl = document.getElementById("modalBaseUrl").value;

    try {
        const res = await fetch("/__sc/security/api/sentinel/config", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                active_provider: pId,
                provider_id: pId,
                api_key: apiKey,
                model: model,
                base_url: baseUrl
            })
        });
        const data = await res.json();
        if (data.success) {
            alert("Configuration enregistrée avec succès !");
            closeByokModal();
            loadProviderConfig();
        }
    } catch (e) {
        alert("Erreur lors de l'enregistrement de la configuration.");
    }
}

async function toggleKillSwitch() {
    const confirmed = confirm("Voulez-vous modifier l'état du Kill-Switch de sécurité ?");
    if (!confirmed) return;

    try {
        const badge = document.getElementById("guardianBadge");
        const isCurrentActive = badge.classList.contains("killed");

        const res = await fetch("/__sc/security/api/sentinel/guardian/killswitch", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ activate: !isCurrentActive })
        });
        const data = await res.json();
        updateKillSwitchUI(data.kill_switch_active);
    } catch (e) {
        console.error("Erreur killswitch", e);
    }
}

function updateKillSwitchUI(isActive) {
    const badge = document.getElementById("guardianBadge");
    const btn = document.getElementById("killSwitchBtn");
    if (isActive) {
        badge.classList.add("killed");
        badge.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color: #ef4444;"></i> <span style="color: #ef4444;">KILL-SWITCH ACTIF (Bloqué)</span>`;
        btn.textContent = "Réactiver Guardian";
        btn.style.background = "#10b981";
        btn.style.color = "#fff";
    } else {
        badge.classList.remove("killed");
        badge.innerHTML = `<i class="fa-solid fa-circle-check" style="color: #10b981;"></i> <span style="color: #10b981;">Guardian Zéro-Trust Actif</span>`;
        btn.innerHTML = `<i class="fa-solid fa-power-off"></i> Arrêt d'urgence`;
        btn.style.background = "rgba(239, 68, 68, 0.15)";
        btn.style.color = "#ef4444";
    }
}
