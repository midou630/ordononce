function getFormData() {

    const today =
        new Date();

    const formattedDate =
        today.toLocaleDateString();

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
            document.getElementById("medications").value,

        date:
            formattedDate
    };
}
