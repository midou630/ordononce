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
    // 📄 عرض التحاليل بشكل ثابت (بدون qty)
    // =======================================

    const container =
      document.getElementById("previewAnalyses");

    // تنظيف المحتوى القديم
    container.innerHTML = "";

    // بناء كل تحليل كسطر مستقل
    data.analyses.forEach((analysis, index) => {

        const row = document.createElement("div");

        row.innerText =
            `${index + 1}. ${analysis.name}`;

        container.appendChild(row);
    });

    document.getElementById("previewDate")
        .innerText = data.date;
}
