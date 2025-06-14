#!/usr/bin/env python3
"""
Script to generate a Sankey diagram showing the relationship between software_type, 
programming_language, and CWE from the cve_ids_in_apps_with_cwe.csv data.
The diagram follows a high-tech military HUD theme.
"""

import os
import pandas as pd
import plotly.graph_objects as go


# Define paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data', 'rq1')
RESULTS_DIR = os.path.join(BASE_DIR, 'results', 'rq1')

# Create results directory if it doesn't exist
os.makedirs(RESULTS_DIR, exist_ok=True)

def load_data():
    """Load and preprocess the CVE data."""
    csv_path = os.path.join(DATA_DIR, 'dataset.csv')
    df = pd.read_csv(csv_path)

    # Extract CWE ID number from the CWE-XXX format
    df['cwe_number'] = df['cwe_id'].str.extract(r'CWE-(\d+)').astype(int)

    return df

def create_sankey_data(df):
    """Create data for the Sankey diagram."""
    # Group by software_type, language, and cwe_id and count occurrences
    grouped = df.groupby(['software_type', 'language', 'cwe_id']).size().reset_index(name='count')

    # Filter to include only relationships with significant counts (optional)
    min_count = 50  # Adjust this threshold as needed
    grouped = grouped[grouped['count'] >= min_count]

    # Create unique lists of nodes
    software_types = grouped['software_type'].unique().tolist()
    languages = grouped['language'].unique().tolist()
    cwe_ids = grouped['cwe_id'].unique().tolist()

    # Create node labels
    node_labels = software_types + languages + cwe_ids

    # Create mapping dictionaries for indices
    software_type_to_idx = {software: idx for idx, software in enumerate(software_types)}
    language_to_idx = {lang: idx + len(software_types) for idx, lang in enumerate(languages)}
    cwe_to_idx = {cwe: idx + len(software_types) + len(languages) for idx, cwe in enumerate(cwe_ids)}

    # Create source, target, and value lists for Sankey diagram
    sources = []
    targets = []
    values = []

    # Software type to language links
    for _, row in grouped.groupby(['software_type', 'language']).sum().reset_index().iterrows():
        sources.append(software_type_to_idx[row['software_type']])
        targets.append(language_to_idx[row['language']])
        values.append(row['count'])

    # Language to CWE links
    for _, row in grouped.groupby(['language', 'cwe_id']).sum().reset_index().iterrows():
        sources.append(language_to_idx[row['language']])
        targets.append(cwe_to_idx[row['cwe_id']])
        values.append(row['count'])

    return {
        'node_labels': node_labels,
        'sources': sources,
        'targets': targets,
        'values': values,
        'software_types_count': len(software_types),
        'languages_count': len(languages),
        'cwe_ids_count': len(cwe_ids)
    }

def create_military_hud_theme():
    """Create a serene, layered military-style Sankey theme suitable for papers."""
    return {
        'bgcolor': '#EAEAF2',  # Light background for paper clarity
        'font': {
            'family': 'Arial, sans-serif',
            'size': 20,
            'color': '#002200'  # Deep green for contrast
        },
        'node': {
            'pad': 30,
            'thickness': 30,
            'line': {
                'color': '#004422',
                'width': 1.5
            },
            'color': [
                # --- Layer 1: Military Greens ---
                '#004D40', '#00695C', '#00796B', '#00897B',
                '#009688', '#26A69A', '#4DB6AC', '#80CBC4',

                # --- Layer 2: Blues ---
                '#1A237E', '#283593', '#303F9F', '#3949AB',
                '#3F51B5', '#5C6BC0', '#7986CB', '#9FA8DA',

                # --- Layer 3: Purples ---
                '#311B92', '#4527A0', '#512DA8', '#5E35B1',
                '#673AB7', '#7E57C2', '#9575CD', '#B39DDB'
            ]
        },
        'link': {
            'color': '#22553333',  # Subtle military olive green, light transparency
            'colorscale': 'Viridis'
        }
    }


def get_layered_link_colors(sources, num_input_nodes, num_middle_nodes):
    """Assign link colors based on source node layer."""
    link_colors = []
    for s in sources:
        if s < num_input_nodes:
            # Input layer (green family)
            link_colors.append('rgba(0,105,92,0.35)')  # dark teal
        elif s < num_input_nodes + num_middle_nodes:
            # Middle layer (blue family)
            link_colors.append('rgba(26,35,126,0.35)')  # deep blue
        else:
            # Output layer (purple family)
            link_colors.append('rgba(49,27,146,0.35)')  # deep purple
    return link_colors


def plot_sankey_diagram(df):
    """Create and save a Sankey diagram with a military HUD theme."""
    sankey_data = create_sankey_data(df)
    # Apply military HUD theme
    theme = create_military_hud_theme()

    # Define how many nodes per layer
    num_input_nodes = 8
    num_middle_nodes = 8

    # Generate link colors based on the source node's layer
    link_colors = get_layered_link_colors(
        sankey_data['sources'], num_input_nodes, num_middle_nodes
    )

    # Create figure
    fig = go.Figure(data=[go.Sankey(
        arrangement='snap',
        node=dict(
            pad=theme['node']['pad'],
            thickness=theme['node']['thickness'],
            line=theme['node']['line'],
            label=sankey_data['node_labels'],
            color=theme['node']['color'][:len(sankey_data['node_labels'])]
        ),
        link=dict(
            source=sankey_data['sources'],
            target=sankey_data['targets'],
            value=sankey_data['values'],
            color=link_colors
        )
    )])

    fig.update_layout(
        #title_text="Vulnerability Relationships: Software Type → Language → CWE",
        #title_font=dict(size=24, color=theme['font']['color']),
        font=theme['font'],
        paper_bgcolor=theme['bgcolor'],
        plot_bgcolor=theme['bgcolor'],
        width=1200,
        height=800,
        margin=dict(l=20, r=20, t=20, b=20)
    )

    # Add grid lines and other HUD elements
    for i in range(10):
        x_pos = i / 10
        fig.add_shape(
            type="line",
            x0=x_pos, y0=0, x1=x_pos, y1=1,
            line=dict(color="rgba(0,255,0,0.1)", width=1)
        )
        fig.add_shape(
            type="line",
            x0=0, y0=x_pos, x1=1, y1=x_pos,
            line=dict(color="rgba(0,255,0,0.1)", width=1)
        )

    # Save the figure
    #output_path = os.path.join(RESULTS_DIR, 'sankey_software_language_cwe.html')
    #fig.write_html(output_path)

    # Also save as image
    image_path = os.path.join(RESULTS_DIR, 'sankey_software_language_cwe.png')
    fig.write_image(image_path)

    #print(f"Sankey diagram saved to {output_path} and {image_path}")
    print(f"Sankey diagram saved to {image_path}")

    return fig

def plot_stacked_bar_chart_generic(df, category_column, title, legend_title, output_filename):
    """
    Create and save a 100% stacked bar chart for a given category column for each software type.

    Args:
        df: DataFrame containing the data
        category_column: Column name to group by (e.g., 'language' or 'cwe_id')
        title: Title for the chart
        legend_title: Title for the legend
        output_filename: Filename for the output image (without path)
    """
    # Group by software_type and the category column and count occurrences
    grouped = df.groupby(['software_type', category_column]).size().reset_index(name='count')

    # Calculate total count for each category across all software types
    category_totals = grouped.groupby(category_column)['count'].sum().reset_index()

    # Sort categories by total count in descending order
    category_totals = category_totals.sort_values('count', ascending=False)

    # Define threshold for "Others" category (e.g., categories with less than 5% of total)
    total_count = category_totals['count'].sum()
    print(f"Total Count: {total_count}")
    threshold_percent = 5
    threshold_count = total_count * threshold_percent / 100

    # Identify categories to keep and those to group as "Others"
    major_categories = category_totals[category_totals['count'] >= threshold_count][category_column].tolist()

    # Create a copy of the grouped dataframe
    grouped_copy = grouped.copy()

    # Replace low-occurrence categories with "Others"
    grouped_copy.loc[~grouped_copy[category_column].isin(major_categories), category_column] = 'Others'

    # Re-aggregate the counts after grouping
    grouped_agg = grouped_copy.groupby(['software_type', category_column]).sum().reset_index()

    # Pivot the data to get categories as columns and software_types as rows
    pivot_df = grouped_agg.pivot_table(index='software_type', columns=category_column, values='count', fill_value=0)
    print(pivot_df)

    # Calculate percentages for each software type
    pivot_df_percent = pivot_df.div(pivot_df.sum(axis=1), axis=0) * 100
    print(pivot_df_percent)

    # Create figure
    fig = go.Figure()

    # Use a simple pattern for distinguishable colors instead of theme colors
    # This creates a list of distinct colors that are easier to differentiate
    distinct_colors = [
        '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
        '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'
    ]

    # Ensure "Others" is the last category if it exists
    columns = list(pivot_df_percent.columns)
    if 'Others' in columns:
        columns.remove('Others')
        columns.append('Others')

    # Add traces for each category
    for i, category in enumerate(columns):
        fig.add_trace(go.Bar(
            y=pivot_df_percent.index,
            x=pivot_df_percent[category],
            name=category,
            orientation='h',
            marker=dict(
                color=distinct_colors[i % len(distinct_colors)],
                line=dict(color='white', width=0.5)
            )
        ))

    # Update layout
    fig.update_layout(
        title_text=title,
        title_font=dict(size=20, color='#002200'),
        font={'family': 'Arial, sans-serif', 'size': 16, 'color': '#002200'},
        barmode='stack',
        width=1200,
        height=800,
        margin=dict(l=25, r=25, t=50, b=25),
        xaxis=dict(
            title='Percentage (%)',
            tickformat=',.0f',
            range=[0, 100]
        ),
        yaxis=dict(
            title='Software Type',
            categoryorder='total ascending'
        ),
        legend=dict(
            title=legend_title,
            orientation='h',
            yanchor='bottom',
            y=1.02,
            xanchor='right',
            x=1
        )
    )

    # Save the figure
    image_path = os.path.join(RESULTS_DIR, output_filename)
    fig.write_image(image_path)

    print(f"Stacked bar chart saved to {image_path}")

    return fig

def plot_stacked_bar_chart(df):
    """Create and save a 100% stacked bar chart of programming languages for each software type."""
    return plot_stacked_bar_chart_generic(
        df=df,
        category_column='language',
        title="Programming Languages by Software Type (100% Stacked)",
        legend_title="Programming Language",
        output_filename='stacked_bar_software_language.png'
    )

def plot_stacked_bar_chart_cwe(df):
    """Create and save a 100% stacked bar chart of CWE for each software type."""
    return plot_stacked_bar_chart_generic(
        df=df,
        category_column='cwe_id',
        title="CWE Distribution by Software Type (100% Stacked)",
        legend_title="CWE-ID",
        output_filename='stacked_bar_software_cwe.png'
    )

def main():
    """Main function to execute the script."""
    print("Loading data...")
    df = load_data()

    print("Creating Sankey diagram...")
    plot_sankey_diagram(df)

    print("Creating 100% stacked bar chart of languages...")
    #plot_stacked_bar_chart(df)

    print("Creating 100% stacked bar chart of CWEs...")
    #plot_stacked_bar_chart_cwe(df)

    print("Done!")

if __name__ == "__main__":
    main()
