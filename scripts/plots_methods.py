#!/usr/bin/env python3
"""
Script to generate donut charts showing the distribution of data from various CSV files.
Currently supports:
1. CWE-ID distribution from cve_ids_in_apps_with_cwe.csv
2. Software Type distribution from software_type.csv
3. Product Language distribution from products_language.csv

The charts include:
- Labels outside the plot pointing to the slices
- Spacing between slices
- Low occurrence values grouped into an "Others" category for clarity
- Configurable threshold for grouping into "Others" category
"""

import os
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

# Define paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data', 'rq1')
RESULTS_DIR = os.path.join(BASE_DIR, 'results', 'rq1')

# Create results directory if it doesn't exist
os.makedirs(RESULTS_DIR, exist_ok=True)

def load_data(csv_filename='cve_ids_in_apps_with_cwe.csv', column_name='cwe_id'):
    """
    Load and preprocess data from a CSV file.

    Args:
        csv_filename: Name of the CSV file to load (located in DATA_DIR)
        column_name: Name of the column to analyze for distribution

    Returns:
        DataFrame containing the loaded data
    """
    csv_path = os.path.join(DATA_DIR, csv_filename)
    df = pd.read_csv(csv_path)

    # Ensure the required column exists
    if column_name not in df.columns:
        raise ValueError(f"CSV file does not contain '{column_name}' column")

    return df

def create_donut_chart(
        df: pd.DataFrame, column_name: str ='cwe_id', threshold_percent: float = 1, center_text: str = 'Distribution',
        colors: list = px.colors.sequential.deep_r
):
    """
    Create a donut chart showing the distribution of values in a specified column.

    The chart includes:
    - Labels outside the plot pointing to the slices
    - Spacing between slices
    - Low occurrence values grouped into an "Others" category

    Args:
        df: DataFrame containing the data
        column_name: Name of the column to analyze for distribution
        threshold_percent: Percentage threshold below which values will be grouped as "Others"
        center_text: Text to display in the center of the donut chart
        colors: List of colors to use for the donut chart

    Returns:
        Plotly figure object
    """
    # Count occurrences of each value in the specified column
    value_counts = df[column_name].value_counts().reset_index()
    value_counts.columns = [column_name, 'count']

    # Calculate total count
    total_count = value_counts['count'].sum()

    # Calculate percentage for each value
    value_counts['percentage'] = (value_counts['count'] / total_count) * 100

    # Determine threshold count based on percentage
    threshold_count = total_count * threshold_percent / 100

    # Separate major values and those to be grouped as "Others"
    major_values = value_counts[value_counts['count'] >= threshold_count]
    minor_values = value_counts[value_counts['count'] < threshold_count]

    # Create "Others" category if there are any minor values
    if not minor_values.empty:
        others_count = minor_values['count'].sum()
        others_percentage = (others_count / total_count) * 100
        others_row = pd.DataFrame({
            column_name: ['Others'],
            'count': [others_count],
            'percentage': [others_percentage]
        })

        # Combine major values with "Others"
        plot_data = pd.concat([major_values, others_row], ignore_index=True)
    else:
        plot_data = major_values

    # Sort by count in descending order
    plot_data = plot_data.sort_values('count', ascending=False)

    # Ensure "Others" is the last category if it exists
    if 'Others' in plot_data[column_name].values:
        # Move "Others" to the end
        others_row = plot_data[plot_data[column_name] == 'Others']
        plot_data = pd.concat([
            plot_data[plot_data[column_name] != 'Others'],
            others_row
        ], ignore_index=True)

    print(plot_data)

    # Create figure
    fig = go.Figure()

    # Add donut chart trace
    fig.add_trace(go.Pie(
        labels=plot_data[column_name],
        values=plot_data['count'],
        hole=0.65,  # Creates the donut hole
        textposition='outside',  # Position text outside with leader lines
        textinfo='label+percent',  # Show label and percentage on the chart
        pull=[0.01] * len(plot_data),  # Add spacing between slices
        marker=dict(
            colors=colors,
            line=dict(color='white', width=2)
        ),
        # hoverinfo='label+percent+value',  # Show info on hover
        automargin=True,  # Automatically adjust margins for labels
        showlegend=False,  # No need for legend with labels on the chart
        legendgroup=column_name,
    ))

    # Create a single annotation for the center of the donut
    annotations = [
        dict(
            text=f'{center_text}',
            x=0.5, y=0.5,
            font=dict(size=40),
            showarrow=False
        )
    ]

    # Update layout
    fig.update_layout(
        # title_text="Distribution of CWE-IDs in CVE Data",
        # title_font=dict(size=24, color='#002200'),
        font={'family': 'Arial, sans-serif', 'size': 28, 'color': '#002200'},
        width=1000,
        height=1000,
        margin=dict(l=20, r=20, t=20, b=20),  # Increased margins for leader lines
        annotations=annotations,
        showlegend=False  # No need for the default legend
    )

    return fig

def main():
    """Main function to execute the script."""
    try:
        # Create CWE-ID distribution chart
        print("Loading CWE data...")
        cwe_df = load_data(csv_filename='cve_ids_in_apps_with_cwe.csv', column_name='cwe_id')

        print(f"Creating donut chart for {len(cwe_df)} CVE entries...")
        cwe_fig = create_donut_chart(
            cwe_df,
            column_name='cwe_id',
            threshold_percent=2,
            center_text='CWE-ID<br>Distribution'
        )

        # Save the CWE figure
        cwe_image_path = os.path.join(RESULTS_DIR, 'cwe_distribution_donut.png')
        cwe_fig.write_image(cwe_image_path)
        print(f"CWE donut chart saved to {cwe_image_path}")

        # Create Software Type distribution chart
        print("\nLoading software type data...")
        sw_type_df = load_data(csv_filename='software_type.csv', column_name='software_type')

        print(f"Creating donut chart for {len(sw_type_df)} software entries...")
        sw_type_fig = create_donut_chart(
            sw_type_df,
            column_name='software_type',
            threshold_percent=5,  # Higher threshold for software types to group low occurrence types
            center_text='Software Type<br>Distribution',
            colors=px.colors.sequential.Emrld_r
        )

        # Save the Software Type figure
        sw_type_image_path = os.path.join(RESULTS_DIR, 'software_type_distribution_donut.png')
        sw_type_fig.write_image(sw_type_image_path)
        print(f"Software Type donut chart saved to {sw_type_image_path}")

        # Create Programming-Language distribution chart
        print("Loading product-language data...")
        pl_df = load_data(csv_filename='products_language.csv', column_name='language')
        pl_df["language"].fillna('N/A', inplace=True)

        print(f"Creating donut chart for {len(pl_df)} software entries...")
        pl_fig = create_donut_chart(
            pl_df,
            column_name='language',
            threshold_percent=1.5,
            center_text='Product-Language<br>Distribution',
            colors=px.colors.sequential.haline
        )

        # Save the Product-Language figure
        pl_image_path = os.path.join(RESULTS_DIR, 'product_language_distribution_donut.png')
        pl_fig.write_image(pl_image_path)
        print(f"Product-Language donut chart saved to {pl_image_path}")

        print("Done!")

    except Exception as e:
        print(f"Error: {e}")
        raise

if __name__ == "__main__":
    main()
