function renderPrescription(data) {

    document.getElementById("previewDoctorName")
        .innerText = data.doctorName;

    document.getElementById("previewPatientName")
        .innerText = data.patientName;

    document.getElementById("previewPatientAge")
        .innerText = data.patientAge;

    document.getElementById("previewPatientGender")
        .innerText = data.patientGender;

    // =======================================
    // 💊 عرض الأدوية بشكل ثابت (حل المشكلة)
    // =======================================

    const container =
        document.getElementById("previewMedications");

    // تنظيف المحتوى القديم
    container.innerHTML = "";

    // بناء كل دواء كسطر مستقل
    data.medications.forEach((med, index) => {

        const row = document.createElement("div");

        row.innerText =
            `${index + 1}. ${med.name} — ${med.qty} boîtes`;

        container.appendChild(row);
    });

    document.getElementById("previewDate")
        .innerText = data.date;
}
