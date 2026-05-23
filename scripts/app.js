document
    .getElementById("generateBtn")
    .addEventListener("click", async () => {

        const data = getFormData();

        renderPrescription(data);

        await generatePDF();
    });
