/**
 *
 * @author Fahym Abd Elfattah
 */
package fahymAbdElfattah;


import javacard.framework.*;


public class Methode {
    public Methode(){
        
    }
    //____________________Verification du code PIN & code  Administrateur _____________________________
    public static void Do_Verif(byte[] buffer,OwnerPIN codePIN,byte PIN_TENT_MAX,byte PIN_SIZE_MAX,OwnerPIN codeADM,byte ADM_TENT_MAX,byte ADM_SIZE_MAX){
        if(buffer[ISO7816.OFFSET_P1] == 0x00){
            if(codePIN.getTriesRemaining() >= 1){
                if (! codePIN.check(buffer, (short) (ISO7816.OFFSET_CDATA), PIN_SIZE_MAX))
                    ISOException.throwIt( (short) (0x63C0 + (short) codePIN.getTriesRemaining())); // Faux Code PIN
                
            }else {
                ISOException.throwIt( (short)0x6983);
            }
      
        }else if(buffer[ISO7816.OFFSET_P1] == 0x01){
            
            if(codeADM.getTriesRemaining() >= 1){
                if (! codeADM.check(buffer, (short) (ISO7816.OFFSET_CDATA), ADM_SIZE_MAX))
                    ISOException.throwIt( (short) (0x63C0 + (short) codeADM.getTriesRemaining())); // Faux Code PIN
                
            }else {
                ISOException.throwIt( (short)0x6983);
            }
            
        }else if(buffer[ISO7816.OFFSET_P1] != 0x00 && buffer[ISO7816.OFFSET_P1] != 0x01){
            ISOException.throwIt( (short)0x6A86);
        }
            
    }
    
    //________________Débloquer le code PIN_____________________________________
    public static void Do_Debloque(OwnerPIN codePIN){
        codePIN.resetAndUnblock();
    }
    
    //______________Réinitialiser les code PIN et Administrateur________________
    public static void Do_Reset(OwnerPIN codePIN,OwnerPIN codeADM){
        codePIN.reset();
        codeADM.reset();
    }
    
    //_______________________mise à jour du code PIN____________________________
    public static void Do_Maj(byte[] buffer,OwnerPIN codePIN){
        if(!codePIN.isValidated())
            ISOException.throwIt( (short)0x6982);
        if(buffer[ISO7816.OFFSET_LC]!= 4)
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        codePIN.update(buffer, (short)(ISO7816.OFFSET_CDATA), (byte) 4);
        if(!codePIN.check(buffer, (short)(ISO7816.OFFSET_CDATA), (byte) 4))
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);  
    }
    //______________________écrire dans la variable NBRE_FILE___________________
    public static byte NF_Write(byte[] buffer,byte NBRE_FILE){
        if(buffer[ISO7816.OFFSET_LC] != 1){
             ISOException.throwIt( (short)0x6A80);
        }else{
             NBRE_FILE = buffer[ISO7816.OFFSET_CDATA];           
        }
        return (byte)(NBRE_FILE*4);
    }
    //______________________écrire dans la variable SPEC_FILE___________________
    public static byte[] SF_Write(byte[] buffer,byte NBRE_FILE,byte[] SPEC_FILE,byte index_w){
        if(buffer[ISO7816.OFFSET_P2] > NBRE_FILE || buffer[ISO7816.OFFSET_P2] < 0){
            ISOException.throwIt( (short)0x6A80);
        }else{
            if(buffer[ISO7816.OFFSET_LC] != 4){
                ISOException.throwIt( (short)0x6A80);
            }else{
                index_w = buffer[ISO7816.OFFSET_P2] ;
                if(index_w < 4*NBRE_FILE - 1){
                    SPEC_FILE[index_w]   = buffer[ISO7816.OFFSET_CDATA];
                    SPEC_FILE[index_w+1] = buffer[ISO7816.OFFSET_CDATA+1];
                    SPEC_FILE[index_w+2] = buffer[ISO7816.OFFSET_CDATA+2];
                    SPEC_FILE[index_w+3] = buffer[ISO7816.OFFSET_CDATA+3];
                }else
                    ISOException.throwIt( (short)0x6A80);
            }
        }
        return SPEC_FILE;
    }
    //______________________écrire dans la variable FICHIER_____________________
    public static byte[] FH_Write(byte[] buffer,byte[] FICHIER,byte FILE_SELECTED,byte nb_rec){
        byte index_rec = buffer[ISO7816.OFFSET_P2] ;
        //byte nb_rec = buffer[ISO7816.OFFSET_CDATA];
        if(buffer[ISO7816.OFFSET_LC] != 4)
            ISOException.throwIt( (short)0x6A80);
        if(index_rec < nb_rec){
            if(FILE_SELECTED != 0){
                FICHIER[index_rec]= buffer[ISO7816.OFFSET_CDATA];
                FICHIER[index_rec+1]= buffer[ISO7816.OFFSET_CDATA+1];
                FICHIER[index_rec+2]= buffer[ISO7816.OFFSET_CDATA+2];
                FICHIER[index_rec+3]= buffer[ISO7816.OFFSET_CDATA+3];
            }else
               ISOException.throwIt( (short)0x6A80); 
        }else
            ISOException.throwIt( (short)0x6A80);
        return FICHIER ;
    }
    
    //______________________lecture de la variable NBRE_FILE____________________
    public static void NF_Read(APDU apdu,byte[] buffer,byte NBRE_FILE){
        buffer[0] = (byte) (NBRE_FILE) ;
        apdu.setOutgoingAndSend( (short) 0, (short) 1 );
    }
    //______________________lecture de la variable SPEC_FILE____________________
    public static void SF_Read(APDU apdu,byte[] buffer,byte[] SPEC_FILE,byte NBRE_FILE,byte index_r){
        
        index_r =buffer[ISO7816.OFFSET_P2] ;
        if(index_r > NBRE_FILE - 1)
            ISOException.throwIt( (short)0x6A80);
        else{
            buffer[0] = (byte) (SPEC_FILE[index_r]) ;
            buffer[1] = (byte) (SPEC_FILE[index_r+1]) ;
            buffer[2] = (byte) (SPEC_FILE[index_r+2]) ;
            buffer[3] = (byte) (SPEC_FILE[index_r+3]) ;
            apdu.setOutgoingAndSend( (short) 0, (short) 4 );
        }
    }
    //______________________lecture depuis la variable FILE_SELECTED________________
    public static void FS_Read(APDU apdu,byte[] buffer,byte FILE_SELECTED){
        buffer[0] = (byte) (FILE_SELECTED) ;
        apdu.setOutgoingAndSend( (short) 0, (short) 1 );
    }
    //______________________lecture depuis la variable FICHIER_____________________
    public static void FH_Read(APDU apdu,byte[] buffer,byte[] FICHIER,OwnerPIN codePIN,byte FILE_SELECTED,byte nb_rec){
        byte index_rec = buffer[ISO7816.OFFSET_P2] ;
        //byte nb_rec = buffer[ISO7816.OFFSET_CDATA];
        if(codePIN.isValidated()){
            if((index_rec < nb_rec)){
                if(FILE_SELECTED != 0){
                    buffer[0] = (byte) (FICHIER[index_rec]) ;
                    buffer[1] = (byte) (FICHIER[index_rec+1]) ;
                    buffer[2] = (byte) (FICHIER[index_rec+2]) ;
                    buffer[3] = (byte) (FICHIER[index_rec+3]) ;
                    apdu.setOutgoingAndSend( (short) 0, (short) 4 );
                }else
                    ISOException.throwIt( (short)0x6A80);
            }else
                ISOException.throwIt( (short)0x6A80);
        }else
            ISOException.throwIt( (short)0x6982);
    }
    //_____________sélectionner les fichiers crées identifiés par leur FID______
    public static byte Do_Select(byte[] buffer,byte[] SPEC_FILE,byte NBRE_FILE){
        byte FILE_SELECTED = 0;
        boolean find = false ;
        byte FID_r = (byte)buffer[ISO7816.OFFSET_CDATA];
        byte FID_l = (byte)buffer[ISO7816.OFFSET_CDATA +1];
        for(byte j=0 ; j < 4*NBRE_FILE ; j++){
            if((SPEC_FILE[j] == FID_r) && (SPEC_FILE[j+1] == FID_l)){
                FILE_SELECTED = j ;
                find = true ;
            }
        }
        if(find == false)
            ISOException.throwIt( (short)0x6A82);
        return FILE_SELECTED;
    }
}
