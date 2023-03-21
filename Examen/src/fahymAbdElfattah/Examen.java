
/**
 * Card Number 14
 * @author Fahym Abd Elfattah & Izeria Younes
 */
package fahymAbdElfattah;

import javacard.framework.*;


public class Examen extends Applet {
    Methode methode = new Methode();
    
    //___________________________APDU COMMANDE__________________________________
    private final static byte CLA               = (byte) 0x80;
    private final static byte INS_VERIF         = (byte) 0x20;
    private final static byte INS_DEBLOQUE_PIN  = (byte) 0x21;
    private final static byte INS_RESET_ADM_PIN = (byte) 0x23;
    private final static byte INS_WRITE         = (byte) 0xB2;
    private final static byte INS_READ          = (byte) 0xD2;
    private final static byte INS_MAJ_PIN        = (byte) 0x22;
    private final static byte INS_SELECT        = (byte) 0xA4;
    
    //____________Vérification Du  Code PIN_____________________________________
    private final static byte PIN_TENT_MAX =  0x03;//Le Nombre de Tentative Maximale
    private final static byte PIN_SIZE_MAX =  0x04;//La Taille du Code PIN
    private final static byte[] PIN_INITIAL = {0x01,0x01,0x01,0x01};
    private static OwnerPIN codePIN;
    
    //____________Vérification Du  Code  Administrateur_________________________
    private final static byte ADM_TENT_MAX =  0x03;//Le Nombre de Tentative Maximale
    private final static byte ADM_SIZE_MAX =  0x06;//La Taille du Code  Administrateur
    private final static byte[] ADM_INITIAL = {0x53,0x45,0x53,0x4E,0x75,0x6D};
    private static OwnerPIN codeADM;
    
    //_________________Déclaration Des Variables NBRE_FILE |SPEC_FILE___________
    byte NBRE_FILE = 0; // Taille = 1 octet, Valeur initiale = 0
    final byte NBRE_FILE_MAX = 5;// Définition de la valeur maximale de NBRE_FILE
    byte[] SPEC_FILE = new byte[4*NBRE_FILE];
    byte index_w = 0 ;
    byte index_r = 0 ;
    byte FILE_SELECTED = -1 ;
    byte Taille = 0;
    byte[] FICHIER ;
    byte nb_rec =0  ;
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Examen();
    }

    
    protected Examen() {
        register();
        //_______L'instanciation & Initialisation Du Code Administrateur________
        codeADM = new OwnerPIN(ADM_TENT_MAX, ADM_SIZE_MAX);
        codeADM.update(ADM_INITIAL, (short) 0, ADM_SIZE_MAX); // (La valeur Initiale,L'offset du Vecteur,Nb D'octet a Lire)
        
        //___________L'instanciation & Initialisation Du Code PIN_______________
        codePIN = new OwnerPIN(PIN_TENT_MAX, PIN_SIZE_MAX);
        codePIN.update(PIN_INITIAL, (short) 0, PIN_SIZE_MAX); // (La valeur Initiale,L'offset du Vecteur,Nb D'octet a Lire)
        
        //_____________Initialisation des enregistrements à 0___________________
        for (byte i = 0; i < 4*NBRE_FILE; i++) {
            SPEC_FILE[i] = 0;
        }
        
        
        
    }

   
    public void process(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        if( selectingApplet()) {
            return; 
        }
        //___________Verification de La Classe de L'aplet_______________________
        if (buffer[ISO7816.OFFSET_CLA] != CLA){ 
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
//______________________________________________________________________________
        switch (buffer[ISO7816.OFFSET_INS]){
            case INS_VERIF : {
                methode.Do_Verif(buffer, codePIN, PIN_TENT_MAX, PIN_SIZE_MAX, codeADM, ADM_TENT_MAX, ADM_SIZE_MAX);
                return;
            }
            case INS_DEBLOQUE_PIN :{
                if(codeADM.isValidated())
                    methode.Do_Debloque(codePIN);
                else
                    ISOException.throwIt( (short)0x6982);
                return;
            }
            case INS_RESET_ADM_PIN :{
                methode.Do_Reset(codePIN, codeADM);
                return;
            }
            case INS_MAJ_PIN :{
                if(codeADM.isValidated())
                    methode.Do_Maj(buffer, codePIN);
                else
                    ISOException.throwIt( (short)0x6982);
                return;
            }
            case INS_WRITE :{
                if(codeADM.isValidated()){
                    if(buffer[ISO7816.OFFSET_P1] == 0x01){
                        NBRE_FILE = methode.NF_Write(buffer,NBRE_FILE);
                        SPEC_FILE = new byte[4*NBRE_FILE];   
                    }else if(buffer[ISO7816.OFFSET_P1] == 0x02){
                        index_w = buffer[ISO7816.OFFSET_P2] ;
                        
                        SPEC_FILE = methode.SF_Write(buffer, NBRE_FILE, SPEC_FILE, index_w);
                        Taille = (byte)(Taille + (byte)(SPEC_FILE[index_w]*SPEC_FILE[index_w +1])) ;
                        FICHIER = new byte[Taille];
                    }else if(buffer[ISO7816.OFFSET_P1] == 0x04){
                        nb_rec = buffer[ISO7816.OFFSET_CDATA];
                        FICHIER = methode.FH_Write(buffer, FICHIER, FILE_SELECTED,nb_rec);
                    }
                }else
                    ISOException.throwIt( (short)0x6982);
                return;
            }
            case INS_READ :{
                if(codeADM.isValidated()){
                    if(buffer[ISO7816.OFFSET_P1] == 0x01){
                        methode.NF_Read(apdu, buffer, NBRE_FILE);
                    }else if(buffer[ISO7816.OFFSET_P1] == 0x02){
                        index_r = buffer[ISO7816.OFFSET_P2] ;
                        methode.SF_Read(apdu, buffer, SPEC_FILE, NBRE_FILE, index_r);
                    }else if(buffer[ISO7816.OFFSET_P1] == 0x03){
                        methode.FS_Read(apdu, buffer, FILE_SELECTED);
                    }else if(buffer[ISO7816.OFFSET_P1] == 0x04){
                        methode.FH_Read(apdu, buffer, FICHIER, codePIN, FILE_SELECTED,nb_rec);
                    }
                }else
                    ISOException.throwIt( (short)0x6982);
                return;
            }
            case INS_SELECT :{
                if(codeADM.isValidated())
                   FILE_SELECTED = methode.Do_Select(buffer, SPEC_FILE, NBRE_FILE);
                else
                    ISOException.throwIt( (short)0x6982);
                return;
            }
            default : {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);//Cas D'erreur ou Avertissement "Commande Inconnue"
            }
            
            
        }
    }
}
