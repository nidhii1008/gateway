const ctx = document.getElementById('myPieChart').getContext('2d');
    let myPieChart;

    const dataMap = {
      option1: [40, 30, 30],
      option2: [10, 50, 40],
      option3: [20, 20, 60],
      option4: [25, 35, 40],
    };

    function updateChart() {
      const selectedOption = document.getElementById('colors').value;
      const data = dataMap[selectedOption];

      if (myPieChart) {
        myPieChart.destroy();
      }

      // Show the loading message

      setTimeout(() => {
        myPieChart = new Chart(ctx, {
          type: 'pie',
          data: {
            labels: ['Assigned', 'Unassigned', 'Repair'],
            datasets: [{
              data: data,
              backgroundColor: ['rgb(45, 194, 107)', 'rgb(40, 81, 158)', 'red'],
              borderWidth: 1
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                  labels: {
                      font: {
                          size: 10
                      }
                  }
              }
          }

          }
        });

        // Hide the loading message and show the chart
        document.getElementById('chart-container').style.opacity = 1;
      }); // Simulating a 2-second delay for the loading effect (you can adjust the delay as needed)
    }

    // Initial chart update on page load
    window.addEventListener('load', updateChart);