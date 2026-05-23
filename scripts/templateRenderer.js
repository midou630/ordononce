function renderPrescription(data) {

    document.getElementById("previewDoctorName")
        .innerText = data.doctorName;

    document.getElementById("previewPatientName")
        .innerText = data.patientName;

    document.getElementById("previewPatientAge")
        .innerText = data.patientAge;

    document.getElementById("previewDiagnosis")
        .innerText = data.diagnosis;

    document.getElementById("previewMedications")
        .innerText = data.medications;

    document.getElementById("previewInstructions")
        .innerText = data.instructions;

    document.getElementById("previewDate")
        .innerText = data.date;
}
