/*
 *   Copyright 2004 The Apache Software Foundation
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
package org.apache.ldap.server.db.gui;


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import javax.swing.*;


/**
 * An about dialog for the introspector GUI.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class AboutDialog extends JDialog
{
    private static final long serialVersionUID = 3257853194544952884L;

    private String title = "About";
    private String product = "Eve jdbm partition inspector";
    private String version = "0.1";
    private String copyright = "Copyright (c) 2003";
    private String comments =
        "This is the jdbm partition viewer or introspector.\nIrregular behavior "
      + "can be analyzed by using this tool to inspect\nthe state of system "
      + "indices and entry attributes within the partition's database.";
    private JPanel contentPane = new JPanel();
    private JLabel prodLabel = new JLabel();
    private JLabel verLabel = new JLabel();
    private JLabel copLabel = new JLabel();
    private JTextArea commentField = new JTextArea();
    private JPanel btnPanel = new JPanel();
    private JButton okButton = new JButton();
    private JLabel image = new JLabel();
    private BorderLayout formLayout = new BorderLayout();
    private GridBagLayout contentPaneLayout = new GridBagLayout();
    private FlowLayout btnPaneLayout = new FlowLayout();
    private JPanel jPanel1 = new JPanel();
    private JPanel jPanel2 = new JPanel();


    /** Creates new About Dialog */
    public AboutDialog(Frame parent, boolean modal)
    {
        super(parent, modal);
        initGUI();
        pack();
    }


    public AboutDialog()
    {
        super();
        setModal(true);
        initGUI();
        pack();
    }


    /** This method is called from within the constructor to initialize the dialog. */
    private void initGUI()
    {
        addWindowListener(
            new java.awt.event.WindowAdapter() {
                public void windowClosing(WindowEvent evt) {
                    closeDialog(evt);
                }
            });
        getContentPane().setLayout(formLayout);
        contentPane.setLayout(contentPaneLayout);
        contentPane.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createLineBorder(
        new java.awt.Color(153, 153, 153), 1), "Directory Project: Eve", javax.swing.border.TitledBorder.LEADING, javax.swing.border.TitledBorder.TOP,
        new java.awt.Font("SansSerif", 0, 14), new java.awt.Color(60, 60, 60)));
        prodLabel.setText(product);
        prodLabel.setAlignmentX(0.5f);
        contentPane.add(prodLabel,
        new java.awt.GridBagConstraints(java.awt.GridBagConstraints.RELATIVE, java.awt.GridBagConstraints.RELATIVE,
        java.awt.GridBagConstraints.REMAINDER, 1, 0.0, 0.0, java.awt.GridBagConstraints.NORTHWEST, java.awt.GridBagConstraints.NONE,
        new java.awt.Insets(5, 5, 0, 0), 5, 0));
        verLabel.setText(version);
        contentPane.add(verLabel,
        new java.awt.GridBagConstraints(java.awt.GridBagConstraints.RELATIVE, java.awt.GridBagConstraints.RELATIVE,
        java.awt.GridBagConstraints.REMAINDER, 1, 0.0, 0.0, java.awt.GridBagConstraints.NORTHWEST, java.awt.GridBagConstraints.NONE,
        new java.awt.Insets(5, 5, 0, 0), 0, 0));
        copLabel.setText(copyright);
        contentPane.add(copLabel,
        new java.awt.GridBagConstraints(java.awt.GridBagConstraints.RELATIVE, java.awt.GridBagConstraints.RELATIVE,
        java.awt.GridBagConstraints.REMAINDER, 1, 0.0, 0.0, java.awt.GridBagConstraints.NORTHWEST, java.awt.GridBagConstraints.NONE,
        new java.awt.Insets(5, 5, 0, 0), 0, 0));
        commentField.setBackground(getBackground());
        commentField.setForeground(copLabel.getForeground());
        commentField.setFont(copLabel.getFont());
        commentField.setText(comments);
        commentField.setEditable(false);
        commentField.setBorder(null);
        contentPane.add(commentField,
        new java.awt.GridBagConstraints(java.awt.GridBagConstraints.RELATIVE, java.awt.GridBagConstraints.RELATIVE,
        java.awt.GridBagConstraints.REMAINDER, 3, 0.0, 1.0, java.awt.GridBagConstraints.NORTHWEST, java.awt.GridBagConstraints.BOTH,
        new java.awt.Insets(5, 5, 5, 0), 0, 0));

        image.setText("Eve");
        image.setIcon( new ImageIcon( getClass().getResource( "server.gif" ) ) );

        image.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
        image.setMinimumSize(new java.awt.Dimension(98,44));
        image.setMaximumSize(new java.awt.Dimension(98,44));
        image.setAlignmentX(0.5f);
        image.setBorder(javax.swing.BorderFactory.createEmptyBorder());
        image.setPreferredSize(new java.awt.Dimension(98,44));
        image.setSize(new java.awt.Dimension(98,200));
        btnPanel.setLayout(btnPaneLayout);
        okButton.setText("OK");
        okButton.addActionListener(
            new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    setVisible(false);
                    dispose();
                }
            });
        btnPanel.add(okButton);
        getContentPane().add(image, BorderLayout.WEST);
        getContentPane().add(contentPane, BorderLayout.CENTER);
        getContentPane().add(btnPanel, BorderLayout.SOUTH);
        getContentPane().add(jPanel1, java.awt.BorderLayout.NORTH);
        getContentPane().add(jPanel2, java.awt.BorderLayout.EAST);
        setTitle(title);
        setResizable(false);
        setFont(new java.awt.Font("Dialog",java.awt.Font.BOLD,12));
        formLayout.setHgap(15);
        jPanel1.setMinimumSize(new java.awt.Dimension(10, 30));
        jPanel1.setPreferredSize(new java.awt.Dimension(10, 30));
        jPanel1.setSize(new java.awt.Dimension(564, 35));
        jPanel2.setMinimumSize(new java.awt.Dimension(72, 165));
        jPanel2.setPreferredSize(new java.awt.Dimension(80, 165));
        jPanel2.setSize(new java.awt.Dimension(72, 170));
        jPanel2.setMaximumSize(new java.awt.Dimension(80,165));
    }


    /** Closes the dialog */
    private void closeDialog(WindowEvent evt)
    {
        evt.getWindow();
        setVisible( false );
        dispose();
    }
}
