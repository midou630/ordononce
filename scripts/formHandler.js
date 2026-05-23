function getFormData() {

    return {

        doctorName:
            document.getElementById("doctorName").value,

        patientName:
            document.getElementById("patientName").value,

        patientAge:
            document.getElementById("patientAge").value,

        diagnosis:
            document.getElementById("diagnosis").value,

        medications:
            document.getElementById("medications").value,

        instructions:
            document.getElementById("instructions").value,

        date:
            document.getElementById("date").value
    };
}
