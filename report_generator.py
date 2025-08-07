import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

class ReportGenerator:
    """
    Gerador de relatórios de auditoria em múltiplos formatos (PDF, Markdown, JSON).
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Inicializa o gerador de relatórios.
        
        Args:
            output_dir: Diretório para salvar os relatórios
        """
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        
        # Cria diretório de saída se não existir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Configuração de estilos para PDF
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """
        Configura estilos customizados para o PDF.
        """
        # Estilo para título principal
        if 'CustomTitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomTitle',
                parent=self.styles['Title'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            ))
        
        # Estilo para subtítulos
        if 'CustomHeading2' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomHeading2',
                parent=self.styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkblue,
                borderWidth=1,
                borderColor=colors.darkblue,
                borderPadding=5
            ))
        
        # Estilo para vulnerabilidades críticas
        if 'CriticalVuln' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CriticalVuln',
                parent=self.styles['Normal'],
                fontSize=12,
                textColor=colors.red,
                backColor=colors.mistyrose,
                borderWidth=1,
                borderColor=colors.red,
                borderPadding=5,
                spaceAfter=10
            ))
        
        # Estilo para vulnerabilidades altas
        if 'HighVuln' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='HighVuln',
                parent=self.styles['Normal'],
                fontSize=12,
                textColor=colors.darkorange,
                backColor=colors.papayawhip,
                borderWidth=1,
                borderColor=colors.darkorange,
                borderPadding=5,
                spaceAfter=10
            ))
        
        # Estilo para código
        if 'CustomCode' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomCode',
                parent=self.styles['Normal'],
                fontSize=10,
                fontName='Courier',
                backColor=colors.lightgrey,
                borderWidth=1,
                borderColor=colors.grey,
                borderPadding=5,
                spaceAfter=10
            ))
    
    def _get_severity_color(self, severity: str) -> colors.Color:
        """
        Retorna cor baseada na severidade.
        
        Args:
            severity: Nível de severidade
            
        Returns:
            Cor correspondente
        """
        color_map = {
            'critical': colors.red,
            'high': colors.darkorange,
            'medium': colors.gold,
            'low': colors.yellow,
            'info': colors.lightblue
        }
        return color_map.get(severity.lower(), colors.grey)
    
    def generate_pdf_report(self, analysis_result: Dict[str, Any], contract_info: Dict[str, Any]) -> str:
        """
        Gera relatório em formato PDF.
        
        Args:
            analysis_result: Resultado da análise de segurança
            contract_info: Informações do contrato
            
        Returns:
            Caminho do arquivo PDF gerado
        """
        contract_address = analysis_result.get('contract_address', 'unknown')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{contract_address}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            doc = SimpleDocTemplate(filepath, pagesize=A4)
            story = []
            
            # Título
            title = f"Relatório de Auditoria de Segurança<br/>Smart Contract: {contract_address}"
            story.append(Paragraph(title, self.styles['CustomTitle']))
            story.append(Spacer(1, 20))
            
            # Informações gerais
            story.append(Paragraph("Informações Gerais", self.styles['CustomHeading2']))
            
            general_info = [
                ['Endereço do Contrato:', contract_address],
                ['Data da Análise:', analysis_result.get('started_at', datetime.now()).strftime("%d/%m/%Y %H:%M:%S")],
                ['Status:', analysis_result.get('status', 'N/A')],
                ['Duração da Análise:', f"{analysis_result.get('duration_seconds', 0):.2f} segundos"],
                ['Ferramentas Utilizadas:', ', '.join(analysis_result.get('tools_used', []))],
                ['Nome do Contrato:', contract_info.get('metadata', {}).get('contract_name', 'N/A')],
                ['Versão do Compilador:', contract_info.get('metadata', {}).get('compiler_version', 'N/A')],
                ['Otimização Habilitada:', 'Sim' if contract_info.get('metadata', {}).get('optimization_used') else 'Não']
            ]
            
            general_table = Table(general_info, colWidths=[2*inch, 4*inch])
            general_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(general_table)
            story.append(Spacer(1, 20))
            
            # Resumo de risco
            risk_assessment = analysis_result.get('risk_assessment', {})
            story.append(Paragraph("Avaliação de Risco", self.styles['CustomHeading2']))
            
            risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
            risk_score = risk_assessment.get('normalized_score', 0)
            total_vulns = risk_assessment.get('total_vulnerabilities', 0)
            
            risk_text = f"""
            <b>Nível de Risco:</b> {risk_level}<br/>
            <b>Pontuação de Risco:</b> {risk_score}/100<br/>
            <b>Total de Vulnerabilidades:</b> {total_vulns}
            """
            
            risk_style = 'CriticalVuln' if risk_level in ['CRITICAL', 'HIGH'] else 'Normal'
            story.append(Paragraph(risk_text, self.styles[risk_style]))
            story.append(Spacer(1, 20))
            
            # Distribuição por severidade
            severity_counts = risk_assessment.get('severity_counts', {})
            if any(severity_counts.values()):
                story.append(Paragraph("Distribuição por Severidade", self.styles['CustomHeading2']))
                
                severity_data = [['Severidade', 'Quantidade', 'Percentual']]
                for severity, count in severity_counts.items():
                    if count > 0:
                        percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
                        severity_data.append([severity.upper(), str(count), f"{percentage:.1f}%"])
                
                severity_table = Table(severity_data, colWidths=[2*inch, 1*inch, 1*inch])
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(severity_table)
                story.append(Spacer(1, 20))
            
            # Vulnerabilidades detalhadas
            vulnerabilities = analysis_result.get('vulnerabilities', [])
            if vulnerabilities:
                story.append(Paragraph("Vulnerabilidades Encontradas", self.styles['CustomHeading2']))
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    story.append(PageBreak())
                    
                    # Título da vulnerabilidade
                    vuln_title = f"{i}. {vuln.get('title', 'Vulnerabilidade')}"
                    story.append(Paragraph(vuln_title, self.styles['Heading3']))
                    
                    # Detalhes da vulnerabilidade
                    vuln_details = [
                        ['Severidade:', vuln.get('severity', 'N/A').upper()],
                        ['Categoria:', vuln.get('category', 'N/A')],
                        ['Ferramenta:', vuln.get('tool', 'N/A')],
                        ['Confiança:', vuln.get('confidence', 'N/A')],
                        ['Linha:', str(vuln.get('line_number', 'N/A'))],
                        ['Função:', vuln.get('function_name', 'N/A')]
                    ]
                    
                    vuln_table = Table(vuln_details, colWidths=[1.5*inch, 4.5*inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    story.append(vuln_table)
                    story.append(Spacer(1, 10))
                    
                    # Descrição
                    if vuln.get('description'):
                        story.append(Paragraph("<b>Descrição:</b>", self.styles['Normal']))
                        story.append(Paragraph(vuln['description'], self.styles['Normal']))
                        story.append(Spacer(1, 10))
                    
                    # Código afetado
                    if vuln.get('code_snippet'):
                        story.append(Paragraph("<b>Código Afetado:</b>", self.styles['Normal']))
                        code_text = vuln['code_snippet'].replace('<', '&lt;').replace('>', '&gt;')
                        story.append(Paragraph(code_text, self.styles['CustomCode']))
                        story.append(Spacer(1, 10))
                    
                    # Recomendação
                    if vuln.get('recommendation'):
                        story.append(Paragraph("<b>Recomendação:</b>", self.styles['Normal']))
                        story.append(Paragraph(vuln['recommendation'], self.styles['Normal']))
                        story.append(Spacer(1, 10))
            
            # Constrói o PDF
            doc.build(story)
            
            self.logger.info(f"Relatório PDF gerado: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório PDF: {e}")
            return ""
    
    def generate_markdown_report(self, analysis_result: Dict[str, Any], contract_info: Dict[str, Any]) -> str:
        """
        Gera relatório em formato Markdown.
        
        Args:
            analysis_result: Resultado da análise de segurança
            contract_info: Informações do contrato
            
        Returns:
            Caminho do arquivo Markdown gerado
        """
        contract_address = analysis_result.get('contract_address', 'unknown')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{contract_address}_{timestamp}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # Cabeçalho
                f.write(f"# Relatório de Auditoria de Segurança\n\n")
                f.write(f"**Smart Contract:** `{contract_address}`\n\n")
                f.write(f"**Data da Análise:** {analysis_result.get('started_at', datetime.now()).strftime('%d/%m/%Y %H:%M:%S')}\n\n")
                f.write("---\n\n")
                
                # Informações gerais
                f.write("## Informações Gerais\n\n")
                f.write(f"- **Endereço do Contrato:** `{contract_address}`\n")
                f.write(f"- **Status da Análise:** {analysis_result.get('status', 'N/A')}\n")
                f.write(f"- **Duração:** {analysis_result.get('duration_seconds', 0):.2f} segundos\n")
                f.write(f"- **Ferramentas Utilizadas:** {', '.join(analysis_result.get('tools_used', []))}\n")
                
                metadata = contract_info.get('metadata', {})
                if metadata:
                    f.write(f"- **Nome do Contrato:** {metadata.get('contract_name', 'N/A')}\n")
                    f.write(f"- **Versão do Compilador:** {metadata.get('compiler_version', 'N/A')}\n")
                    f.write(f"- **Otimização:** {'Habilitada' if metadata.get('optimization_used') else 'Desabilitada'}\n")
                
                f.write("\n")
                
                # Avaliação de risco
                risk_assessment = analysis_result.get('risk_assessment', {})
                if risk_assessment:
                    f.write("## Avaliação de Risco\n\n")
                    
                    risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
                    risk_score = risk_assessment.get('normalized_score', 0)
                    total_vulns = risk_assessment.get('total_vulnerabilities', 0)
                    
                    # Emoji baseado no nível de risco
                    risk_emoji = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢',
                        'MINIMAL': '⚪'
                    }.get(risk_level, '⚫')
                    
                    f.write(f"### {risk_emoji} Nível de Risco: **{risk_level}**\n\n")
                    f.write(f"- **Pontuação de Risco:** {risk_score}/100\n")
                    f.write(f"- **Total de Vulnerabilidades:** {total_vulns}\n\n")
                    
                    # Distribuição por severidade
                    severity_counts = risk_assessment.get('severity_counts', {})
                    if any(severity_counts.values()):
                        f.write("### Distribuição por Severidade\n\n")
                        f.write("| Severidade | Quantidade | Percentual |\n")
                        f.write("|------------|------------|------------|\n")
                        
                        for severity, count in severity_counts.items():
                            if count > 0:
                                percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
                                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}.get(severity, '⚫')
                                f.write(f"| {emoji} {severity.upper()} | {count} | {percentage:.1f}% |\n")
                        
                        f.write("\n")
                
                # Vulnerabilidades
                vulnerabilities = analysis_result.get('vulnerabilities', [])
                if vulnerabilities:
                    f.write("## Vulnerabilidades Encontradas\n\n")
                    
                    for i, vuln in enumerate(vulnerabilities, 1):
                        severity = vuln.get('severity', 'info')
                        severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': '🔵'}.get(severity, '⚫')
                        
                        f.write(f"### {i}. {severity_emoji} {vuln.get('title', 'Vulnerabilidade')}\n\n")
                        
                        # Detalhes em tabela
                        f.write("| Campo | Valor |\n")
                        f.write("|-------|-------|\n")
                        f.write(f"| **Severidade** | {severity.upper()} |\n")
                        f.write(f"| **Categoria** | {vuln.get('category', 'N/A')} |\n")
                        f.write(f"| **Ferramenta** | {vuln.get('tool', 'N/A')} |\n")
                        f.write(f"| **Confiança** | {vuln.get('confidence', 'N/A')} |\n")
                        f.write(f"| **Linha** | {vuln.get('line_number', 'N/A')} |\n")
                        f.write(f"| **Função** | {vuln.get('function_name', 'N/A')} |\n\n")
                        
                        # Descrição
                        if vuln.get('description'):
                            f.write("**Descrição:**\n\n")
                            f.write(f"{vuln['description']}\n\n")
                        
                        # Código afetado
                        if vuln.get('code_snippet'):
                            f.write("**Código Afetado:**\n\n")
                            f.write("```solidity\n")
                            f.write(f"{vuln['code_snippet']}\n")
                            f.write("```\n\n")
                        
                        # Recomendação
                        if vuln.get('recommendation'):
                            f.write("**Recomendação:**\n\n")
                            f.write(f"{vuln['recommendation']}\n\n")
                        
                        f.write("---\n\n")
                
                # Rodapé
                f.write("## Informações Adicionais\n\n")
                f.write("Este relatório foi gerado automaticamente pelo Agente Auditor de Smart Contracts Ethereum.\n")
                f.write(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n")
                f.write("⚠️ **Aviso:** Este relatório é apenas para fins informativos. ")
                f.write("Recomenda-se uma auditoria manual adicional por especialistas em segurança.\n")
            
            self.logger.info(f"Relatório Markdown gerado: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório Markdown: {e}")
            return ""
    
    def generate_json_report(self, analysis_result: Dict[str, Any], contract_info: Dict[str, Any]) -> str:
        """
        Gera relatório em formato JSON.
        
        Args:
            analysis_result: Resultado da análise de segurança
            contract_info: Informações do contrato
            
        Returns:
            Caminho do arquivo JSON gerado
        """
        contract_address = analysis_result.get('contract_address', 'unknown')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{contract_address}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            report_data = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'Ethereum Smart Contract Auditor Agent',
                    'version': '1.0.0',
                    'report_type': 'security_audit'
                },
                'contract_info': contract_info,
                'analysis_result': analysis_result
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
            
            self.logger.info(f"Relatório JSON gerado: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório JSON: {e}")
            return ""
    
    def generate_all_formats(self, analysis_result: Dict[str, Any], contract_info: Dict[str, Any]) -> Dict[str, str]:
        """
        Gera relatórios em todos os formatos disponíveis.
        
        Args:
            analysis_result: Resultado da análise de segurança
            contract_info: Informações do contrato
            
        Returns:
            Dict com caminhos dos arquivos gerados
        """
        reports = {}
        
        try:
            reports['pdf'] = self.generate_pdf_report(analysis_result, contract_info)
            reports['markdown'] = self.generate_markdown_report(analysis_result, contract_info)
            reports['json'] = self.generate_json_report(analysis_result, contract_info)
            
            self.logger.info(f"Relatórios gerados para contrato {analysis_result.get('contract_address', 'unknown')}")
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatórios: {e}")
        
        return reports

