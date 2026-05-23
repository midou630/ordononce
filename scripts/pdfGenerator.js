async function generatePDF() {

    const element =
        document.getElementById("prescriptionTemplate");

    const canvas = await html2canvas(element, {
        scale: 4,
        useCORS: true
    });

    const imgData =
        canvas.toDataURL("image/png");

    const pdf =
        new window.jspdf.jsPDF({
            orientation: "portrait",
            unit: "px",
            format: [794, 1123]
        });

    pdf.addImage(
        imgData,
        "PNG",
        0,
        0,
        794,
        1123
    );

    pdf.save("prescription.pdf");
}
