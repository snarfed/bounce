/** Misc JavaScript.
 */

// Copies an element's data-copy attribute to the clipboard when it's clicked.
document.addEventListener('click', (event) => {
  const elem = event.target.closest('[data-copy]');
  if (elem) {
    navigator.clipboard.writeText(elem.dataset.copy);
  }
});

// Follower and follow pie charts on review.html. The chart data is in each chart
// element's data-counts attribute. Waits for DOMContentLoaded because this file
// loads in <head>, before review.html loads the Google Charts loader.
document.addEventListener('DOMContentLoaded', () => {
  const followers = document.getElementById('followers-chart');
  if (!followers) {
    return;
  }

  google.charts.load('current', {packages: ['corechart']});
  google.charts.setOnLoadCallback(() => {
    const opts = {
      legend: {
        position: 'top',
        alignment: 'center',
        maxLines: 2,
      },
    };

    new google.visualization.PieChart(followers).draw(
      google.visualization.arrayToDataTable(JSON.parse(followers.dataset.counts)), opts);

    const follows = document.getElementById('follows-chart');
    const followCounts = JSON.parse(follows.dataset.counts);
    const unbridgedSlice = followCounts.length - 2;
    opts.slices = {};
    opts.slices[unbridgedSlice] = {
      offset: 0.2,
      color: 'gray',
    };
    new google.visualization.PieChart(follows).draw(
      google.visualization.arrayToDataTable(followCounts), opts);
  });
});
