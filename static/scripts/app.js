let medicationsData = [];
let selectedMedications = [];

// ===============================
// Custom medications (LocalStorage)
// ===============================
let customMedications =
    JSON.parse(localStorage.getItem("customMeds") || "[]");

function saveCustomMeds() {

    localStorage.setItem(
        "customMeds",
        JSON.stringify(customMedications)
    );
}


// ===============================
// Load JSON + merge custom meds
// ===============================
fetch("static/assets/data/medications.json")
    .then(res => res.json())
    .then(data => {

        medicationsData = [
            ...data,
            ...customMedications
        ];
    });


// ===============================
const medInput =
    document.getElementById("medications");

const medList =
    document.getElementById("medicationsList");

const selectedContainer =
    document.getElementById("selectedMeds");


// =======================================
// POPUP: Nombre de boîtes
// =======================================
function askQuantity(callback) {

    const overlay =
        document.createElement("div");

    overlay.style.position = "fixed";
    overlay.style.top = "0";
    overlay.style.left = "0";
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.background = "rgba(0,0,0,0.5)";
    overlay.style.display = "flex";
    overlay.style.justifyContent = "center";
    overlay.style.alignItems = "center";
    overlay.style.zIndex = "99999";

    const box =
        document.createElement("div");

    box.style.background = "white";
    box.style.padding = "20px";
    box.style.borderRadius = "10px";
    box.style.textAlign = "center";

    const input =
        document.createElement("input");

    input.type = "number";
    input.placeholder = "Nombre de boîtes";
    input.style.padding = "10px";
    input.style.width = "100%";

    const btn =
        document.createElement("button");

    btn.innerText = "Valider";
    btn.style.marginTop = "10px";
    btn.style.padding = "8px 15px";

    btn.addEventListener("click", () => {

        const value =
            parseInt(input.value || "1");

        document.body.removeChild(overlay);

        callback(value);
    });

    box.appendChild(input);
    box.appendChild(btn);

    overlay.appendChild(box);

    document.body.appendChild(overlay);
}


// =======================================
// POPUP: Ajouter un médicament
// =======================================
function addNewMedicationPopup() {

    const overlay =
        document.createElement("div");

    overlay.style.position = "fixed";
    overlay.style.top = "0";
    overlay.style.left = "0";
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.background = "rgba(0,0,0,0.6)";
    overlay.style.display = "flex";
    overlay.style.justifyContent = "center";
    overlay.style.alignItems = "center";
    overlay.style.zIndex = "99999";

    const box =
        document.createElement("div");

    box.style.background = "white";
    box.style.padding = "20px";
    box.style.borderRadius = "10px";
    box.style.width = "320px";

    box.innerHTML = `

        <h3>Ajouter un médicament</h3>

        <input
            id="newActive"
            placeholder="Principe actif"
            style="width:100%;margin:5px 0;padding:6px"
        />

        <input
            id="newBrand"
            placeholder="Nom commercial"
            style="width:100%;margin:5px 0;padding:6px"
        />

        <input
            id="newDose"
            placeholder="Dosage (Ex : 10MG)"
            style="width:100%;margin:5px 0;padding:6px"
        />

        <select
            id="newForm"
            style="width:100%;margin:5px 0;padding:6px"
        >

            <option value="COMPRIME">
                COMPRIMÉ
            </option>

            <option value="SIROP">
                SIROP
            </option>

            <option value="INJECTION">
                INJECTION
            </option>

        </select>

        <button
            id="saveMedBtn"
            style="margin-top:10px;padding:8px 15px"
        >

            Ajouter

        </button>
    `;

    overlay.appendChild(box);

    document.body.appendChild(overlay);


    // =======================================
    // Enregistrer le nouveau médicament
    // =======================================
    document
        .getElementById("saveMedBtn")
        .addEventListener("click", () => {

            const active =
                document.getElementById("newActive").value;

            const brand =
                document.getElementById("newBrand").value;

            const dose =
                document.getElementById("newDose").value;

            const form =
                document.getElementById("newForm").value;

            if (!active || !brand)
                return;

            const fullName =
                `${active} ${brand} ${dose} ${form}`;

            customMedications.push(fullName);

            saveCustomMeds();

            medicationsData.push(fullName);

            document.body.removeChild(overlay);

            askQuantity((qty) => {

                selectedMedications.push({

                    name: fullName,
                    qty: qty

                });

                renderSelectedMedications();

                medInput.value = "";

                medList.innerHTML = "";
            });
        });
}
// =======================================
// Affichage de la liste des médicaments
// =======================================
function renderMedicationsList(list) {

    medList.innerHTML = "";

    if (!list.length) {

        medList.innerHTML =
            "<div class='med-item'>Aucun résultat</div>";

        return;
    }

    list.forEach(med => {

        const item =
            document.createElement("div");

        item.className = "med-item";

        item.innerText = med;


        // =======================================
        // Sélection d'un médicament
        // =======================================
        item.addEventListener("click", (e) => {

            e.stopPropagation();

            askQuantity((qty) => {

                selectedMedications.push({

                    name: med,
                    qty: qty

                });

                renderSelectedMedications();

                medInput.value = "";

                medList.innerHTML = "";
            });
        });

        medList.appendChild(item);
    });
}


// =======================================
// Affichage des médicaments sélectionnés
// =======================================
function renderSelectedMedications() {

    selectedContainer.innerHTML = "";

    selectedMedications.forEach((med, index) => {

        const row =
            document.createElement("div");

        row.className = "selected-med";


        const text =
            document.createElement("span");

        text.innerText =
            `${index + 1}. ${med.name} — ${med.qty} boîte(s)`;


        // Bouton supprimer
        const removeBtn =
            document.createElement("button");

        removeBtn.innerText = "❌";

        removeBtn.className = "remove-med";


        removeBtn.addEventListener("click", () => {

            selectedMedications.splice(index, 1);

            renderSelectedMedications();
        });

        row.appendChild(text);

        row.appendChild(removeBtn);

        selectedContainer.appendChild(row);
    });
}


// =======================================
// Ouvrir la liste
// =======================================
medInput.addEventListener("click", (e) => {

    e.stopPropagation();

    renderMedicationsList(medicationsData);
});


// =======================================
// Recherche instantanée
// =======================================
medInput.addEventListener("input", () => {

    const value =
        medInput.value.toLowerCase();

    const filtered =
        medicationsData.filter(med =>

            med.toLowerCase().includes(value)
        );

    renderMedicationsList(filtered);
});


// =======================================
// Bouton Ajouter un médicament
// =======================================
const addMedBtn =
    document.createElement("button");

addMedBtn.innerText =
    "➕ Ajouter un médicament";

addMedBtn.type = "button";

addMedBtn.style.marginTop = "10px";

document
    .querySelector(".form-section")
    .appendChild(addMedBtn);

addMedBtn.addEventListener(
    "click",
    addNewMedicationPopup
);


// =======================================
// Fermer la liste
// =======================================
document.addEventListener("click", () => {

    medList.innerHTML = "";
});


// =======================================
// Génération du PDF
// =======================================
document
    .getElementById("generateBtn")
    .addEventListener("click", async () => {

        const data =
            getFormData();

        renderPrescription(data);

        await generatePDF();
    });


// =======================================
// Récupération des données
// =======================================
function getFormData() {

    return {

        doctorName:
            document.getElementById("doctorName").value,

        patientName:
            document.getElementById("patientName").value,

        patientAge:
            document.getElementById("patientAge").value,

        patientGender:
            document.getElementById("patientGender").value,

        medications:
            selectedMedications,

        date:
            new Date().toLocaleDateString("fr-FR")
    };
}


// =======================================
// Coordonnées de l'ordonnance
// =======================================
const template =
    document.getElementById("prescriptionTemplate");

template.addEventListener("click", (e) => {

    const rect =
        template.getBoundingClientRect();

    const x =
        e.clientX - rect.left;

    const y =
        e.clientY - rect.top;

    console.log("X:", x);

    console.log("Y:", y);

});
