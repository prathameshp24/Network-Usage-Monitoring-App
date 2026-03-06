import matplotlib.pyplot as plt
import csv
import os
from tkinter import messagebox

class Visualization:
    @staticmethod
    def show_pie_chart(websites):
        """Displays a pie chart for website usage."""
        if not websites:
            messagebox.showinfo("No Data", "No website data available.")
            return

        # Extract website names and visit counts
        website_names = list(websites.keys())
        visits = list(websites.values())

        # Calculate total visits for threshold comparison
        total_visits = sum(visits)
        threshold = 0.065 * total_visits  # 6.5% of total visits
        filtered_websites = []
        filtered_visits = []
        other_visits = 0

        # Aggregate visits into "Others" category if below threshold
        for i, visit in enumerate(visits):
            if visit < threshold:
                other_visits += visit
            else:
                filtered_websites.append(website_names[i])
                filtered_visits.append(visit)

        # Add "Others" if applicable
        if other_visits > 0:
            filtered_websites.append("Others")
            filtered_visits.append(other_visits)

        # Ensure there are data points to display
        if not filtered_visits:
            messagebox.showinfo("No Significant Data", "All visits are below the threshold.")
            return

        # Plotting the pie chart
        plt.figure(figsize=(7, 7))
        plt.pie(filtered_visits, labels=filtered_websites, autopct='%1.1f%%', startangle=90)
        plt.title("Website Visits Distribution")
        plt.axis('equal')  # Equal aspect ratio ensures the pie chart is circular.
        plt.show()

    @staticmethod
    def show_network_graph():
        """Displays a network usage graph."""
        file_path = os.path.join('data', 'network_usage.csv')
        if not os.path.exists(file_path):
            messagebox.showinfo("No Data", "No network usage data available.")
            return

        timestamps, downloads, uploads = [], [], []
        with open(file_path, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                timestamps.append(row['Timestamp'])
                downloads.append(int(row['Download']))
                uploads.append(int(row['Upload']))

        # Check if we have data to plot
        if not timestamps:
            messagebox.showinfo("No Data", "No network usage data to display.")
            return

        plt.figure(figsize=(10, 6))
        plt.plot(timestamps, downloads, label='Download', color='b')
        plt.plot(timestamps, uploads, label='Upload', color='r')
        plt.xlabel('Time')
        plt.ylabel('Bytes')
        plt.title('Network Usage Over Time')
        plt.xticks(rotation=45)
        plt.legend()
        plt.tight_layout()
        plt.show()
