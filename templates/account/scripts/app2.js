






let analysesData = [];
let selectedAnalyses = [];

// ===============================
// Analyses personnalisées (LocalStorage)
// ===============================
let customAnalyses =
    JSON.parse(localStorage.getItem("customAnalyses") || "[]");

function saveCustomAnalyses() {

    localStorage.setItem(
        "customAnalyses",
        JSON.stringify(customAnalyses)
    );
}


// ===============================
// Load JSON + merge custom analyses
// ===============================
fetch("assets/data/analyses.json")
    .then(res => res.json())
    .then(data => {

        analysesData = [
            ...data,
            ...customAnalyses
        ];
    });


// ===============================
const medInput =
    document.getElementById("analyses");

const medList =
    document.getElementById("analysesList");

const selectedContainer =
    document.getElementById("selectedAnalyses");

// =======================================
// POPUP : Ajouter une analyse
// =======================================
function addNewAnalysisPopup() {

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

        <h3>Ajouter une analyse</h3>

        <input
            id="newAnalysis"
            placeholder="Nom de l'analyse"
            style="width:100%;margin:10px 0;padding:8px"
        />

        <button
            id="saveAnalysisBtn"
            style="margin-top:10px;padding:8px 15px"
        >
            Ajouter
        </button>
    `;

    overlay.appendChild(box);

    document.body.appendChild(overlay);


    // =======================================
    // Enregistrer la nouvelle analyse
    // =======================================
    document
        .getElementById("saveAnalysisBtn")
        .addEventListener("click", () => {

            const analysis =
                document.getElementById("newAnalysis").value;

            if (!analysis)
                return;

            customAnalyses.push(analysis);

            saveCustomAnalyses();

            analysesData.push(analysis);

            selectedAnalyses.push({
                name: analysis
            });

            renderSelectedAnalyses();

            document.body.removeChild(overlay);

            medInput.value = "";

            medList.innerHTML = "";
        });
}


// =======================================
// Affichage de la liste des analyses
// =======================================
function renderMedicationsList(list) {

    medList.innerHTML = "";

    if (!list.length) {

        medList.innerHTML =
            "<div class='med-item'>Aucun résultat</div>";

        return;
    }
    list.forEach(analysis => {

        const item =
            document.createElement("div");

        item.className = "med-item";

        item.innerText = analysis;


        // =======================================
        // Sélection d'une analyse
        // =======================================
        item.addEventListener("click", (e) => {

            e.stopPropagation();

            selectedAnalyses.push({

                name: analysis

            });

            renderSelectedAnalyses();

            medInput.value = "";

            medList.innerHTML = "";
        });

        medList.appendChild(item);
    });
}


// =======================================
// Affichage des analyses sélectionnées
// =======================================
function renderSelectedAnalyses() {

    selectedContainer.innerHTML = "";

    selectedAnalyses.forEach((analysis, index) => {

        const row =
            document.createElement("div");

        row.className = "selected-med";


        const text =
            document.createElement("span");

        text.innerText =
            `${index + 1}. ${analysis.name}`;


        const removeBtn =
            document.createElement("button");

        removeBtn.innerText = "❌";

        removeBtn.className = "remove-med";


        removeBtn.addEventListener("click", () => {

            selectedAnalyses.splice(index, 1);

            renderSelectedAnalyses();
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

    renderMedicationsList(analysesData);
});


// =======================================
// Recherche instantanée
// =======================================
medInput.addEventListener("input", () => {

    const value =
        medInput.value.toLowerCase();

    const filtered =
        analysesData.filter(analysis =>

            analysis.toLowerCase().includes(value)
        );

    renderMedicationsList(filtered);
});


// =======================================
// Bouton Ajouter une analyse
// =======================================
const addMedBtn =
    document.createElement("button");

addMedBtn.innerText =
    "➕ Ajouter une analyse";

addMedBtn.type = "button";

addMedBtn.style.marginTop = "10px";

document
    .querySelector(".form-section")
    .appendChild(addMedBtn);

addMedBtn.addEventListener(
    "click",
    addNewAnalysisPopup
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

        analyses:
            selectedAnalyses,

        date:
            new Date().toLocaleDateString("fr-FR")
    };
}


// =======================================
// Coordonnées du document
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
