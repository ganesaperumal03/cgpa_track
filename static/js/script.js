function goBack() {
  window.history.back();
}

function goForward() {
  window.history.forward();
}


$(document).ready(function(){
    $("#education").on("change",function(){
      var name=$("#education").val();
      $(".Qualified").hide();
      $("."+name).show();
    }).change();
  });


  $(document).ready(function(){
    $("#Quota").on("change",function(){
      var name=$("#Quota").val();
      $(".modify").hide();
      $("."+name).show();
    }).change();
  });

  
  $(document).ready(function(){
    $("#sslcmark").on("change",function(){
      var name=$("#sslcmark").val();
      $(".othersmark").hide();
      $("."+name).show();
    }).change();
  });

  $(document).ready(function(){
    $("#ScholarShip").on("change",function(){
      var name=$("#ScholarShip").val();
      $(".gratuate").hide();
      $("."+name).show();
    }).change();
  });

  $(document).ready(function(){
    $("#preformadmissionfor").on("change",function(){
      var name=$("#preformadmissionfor").val();
      $(".admissionfor").hide();
      $("."+name).show();
    }).change();

  });  $(document).ready(function(){
    $("#preformdiploma").on("change",function(){
      var name=$("#preformdiploma").val();
      $(".diplomachange").hide();
      $("."+name).show();
    }).change();
  });

  $(document).ready(function(){
    $("#Tenth_Std_School_Name").on("change",function(){
      var name=$("#Tenth_Std_School_Name").val();
      $(".tenthschoolchange").hide();
      $("."+name).show();
    }).change();
  });
  $(document).ready(function(){
    $("#Eleventh_Std_School_Name").on("change",function(){
      var name=$("#Eleventh_Std_School_Name").val();
      $(".elcventhchoolchange").hide();
      $("."+name).show();
    }).change();
  });

  $(document).ready(function(){
    $("#Twelfth_Std_School_Name").on("change",function(){
      var name=$("#Twelfth_Std_School_Name").val();
      $(".twelthschoolchange").hide();
      $("."+name).show();
    }).change();
  });


  $(document).ready(function(){
    $("#Diploma_apply_for").on("change",function(){
      var name=$("#Diploma_apply_for").val();
      $(".hscanddiploma").hide();
      $("."+name).show();
    }).change();
  });
  function FillAddressInput()
    {
       let checkBox= document.getElementById('checkBox');

       let Permanent_Address_Door_No = document.getElementById("Permanent_Address_Door_No");
       let Permanent_Address_Street_Name = document.getElementById("Permanent_Address_Street_Name");
       let Permanent_Address_Location = document.getElementById("Permanent_Address_Location");
       let Permanent_Address_Pincode = document.getElementById("Permanent_Address_Pincode");
       let Permanent_Address_Taluk = document.getElementById("Permanent_Address_Taluk");
       let Permanent_Address_District = document.getElementById("Permanent_Address_District");
       let Permanent_Address_State = document.getElementById("Permanent_Address_State");

       let Communication_Address_Door_No = document.getElementById("Communication_Address_Door_No");
       let Communication_Address_Street_Name = document.getElementById("Communication_Address_Street_Name");
       let Communication_Address_Location = document.getElementById("Communication_Address_Location");
       let Communication_Address_Pincode = document.getElementById("Communication_Address_Pincode");
       
       let Communication_Address_Taluk = document.getElementById("Communication_Address_Taluk");
       let Communication_Address_District = document.getElementById("Communication_Address_District");
       let Communication_Address_State = document.getElementById("Communication_Address_State");

        if (checkBox.checked == true)
        {

       let Permanent_Address_Door_NoValue = Permanent_Address_Door_No.value;
       let Permanent_Address_Street_NameValue = Permanent_Address_Street_Name.value;
       let Permanent_Address_LocationValue     = Permanent_Address_Location.value;
       let Permanent_Address_PincodeValue      = Permanent_Address_Pincode.value;
       let Permanent_Address_TalukValue         = Permanent_Address_Taluk.value;
       let Permanent_Address_DistrictValue        = Permanent_Address_District.value;
       let Permanent_Address_StateValue      = Permanent_Address_State.value;

       Communication_Address_Door_No.value = Permanent_Address_Door_NoValue; 
       Communication_Address_Street_Name.value = Permanent_Address_Street_NameValue;
       Communication_Address_Location.value     = Permanent_Address_LocationValue;
       Communication_Address_Pincode.value      = Permanent_Address_PincodeValue;
       Communication_Address_Taluk.value         = Permanent_Address_TalukValue;
       Communication_Address_District.value        = Permanent_Address_DistrictValue;
       Communication_Address_State.value      = Permanent_Address_StateValue;


       }
        else
        {
       Communication_Address_Door_No.value = "";
       Communication_Address_Street_Name.value = "";
       Communication_Address_Location.value     = "";
       Communication_Address_Pincode.value      = "";
       Communication_Address_Taluk.value         = "";
       Communication_Address_District.value        = "";
       Communication_Address_State.value      = "";           }
    }



    function sslcSum() {
      // sslc
      var Tenth_Std_Tamil_Mark = parseInt(document.getElementById("Tenth_Std_Tamil_Mark").value) || 0;
      var Tenth_Std_English_Mark = parseInt(document.getElementById("Tenth_Std_English_Mark").value) || 0;
      var Tenth_Std_Maths_Mark = parseInt(document.getElementById("Tenth_Std_Maths_Mark").value) || 0;
      var Tenth_Std_Science_Mark = parseInt(document.getElementById("Tenth_Std_Science_Mark").value) || 0;
      var Tenth_Std_SocialScience_Mark = parseInt(document.getElementById("Tenth_Std_SocialScience_Mark").value) || 0;
      var Tenth_Std_Others_Mark = parseInt(document.getElementById("Tenth_Std_Others_Mark").value) || 0;
      var Tenth_Std_Total_Mark = (Tenth_Std_Tamil_Mark + Tenth_Std_English_Mark + Tenth_Std_Maths_Mark + Tenth_Std_Science_Mark + Tenth_Std_SocialScience_Mark+ Tenth_Std_Others_Mark) .toFixed(2) ;
      document.getElementById("Tenth_Std_Total_Mark").value = Tenth_Std_Total_Mark;
    }
    function hscacaSum() {
      // academic
      var Twelfth_Std_aca_Language_Mark = parseInt(document.getElementById("Twelfth_Std_aca_Language_Mark").value) || 0;
      var Twelfth_Std_aca_English_Mark = parseInt(document.getElementById("Twelfth_Std_aca_English_Mark").value) || 0;
      var Twelfth_Std_aca_Mathematics_Mark = parseInt(document.getElementById("Twelfth_Std_aca_Mathematics_Mark").value) || 0;
      var Twelfth_Std_aca_Physics_Mark = parseInt(document.getElementById("Twelfth_Std_aca_Physics_Mark").value) || 0;
      var Twelfth_Std_aca_Chemistry_Mark = parseInt(document.getElementById("Twelfth_Std_aca_Chemistry_Mark").value) || 0;
      var Twelfth_Std_aca_Elective_Mark = parseInt(document.getElementById("Twelfth_Std_aca_Elective_Mark").value) || 0;
      var Twelfth_Std_aca_Total_Marks = (Twelfth_Std_aca_Language_Mark + Twelfth_Std_aca_English_Mark + Twelfth_Std_aca_Mathematics_Mark + Twelfth_Std_aca_Physics_Mark + Twelfth_Std_aca_Chemistry_Mark + Twelfth_Std_aca_Elective_Mark) .toFixed(2) ;
      var Twelfth_Std_aca_CUT_OFF_Mark = ( Twelfth_Std_aca_Mathematics_Mark + ((Twelfth_Std_aca_Physics_Mark + Twelfth_Std_aca_Chemistry_Mark)/2)) .toFixed(2) ;
      var Twelfth_Std_aca_PCM_Average = (( Twelfth_Std_aca_Mathematics_Mark + Twelfth_Std_aca_Physics_Mark + Twelfth_Std_aca_Chemistry_Mark)/3 ) .toFixed(2) ;
    
      document.getElementById("Twelfth_Std_aca_Total_Marks").value = Twelfth_Std_aca_Total_Marks;
      document.getElementById("Twelfth_Std_aca_CUT_OFF_Mark").value = Twelfth_Std_aca_CUT_OFF_Mark;
      document.getElementById("Twelfth_Std_aca_PCM_Average").value = Twelfth_Std_aca_PCM_Average;
    }
    function hscvocSum() {
      // Fetch input values and convert them to numbers
      var Twelfth_Std_voc_Language_Mark = parseInt(document.getElementById("Twelfth_Std_voc_Language_Mark").value) || 0;
      var Twelfth_Std_voc_English_Mark = parseInt(document.getElementById("Twelfth_Std_voc_English_Mark").value) || 0;
      var Twelfth_Std_voc_chemistry_Mark = parseInt(document.getElementById("Twelfth_Std_voc_chemistry_Mark").value) || 0;
      var Twelfth_Std_voc_Mathematics_or_Physics_Mark = parseInt(document.getElementById("Twelfth_Std_voc_Mathematics_or_Physics_Mark").value) || 0;
      var Twelfth_Std_voc_Vocational_Theory_Mark = parseInt(document.getElementById("Twelfth_Std_voc_Vocational_Theory_Mark").value) || 0;
      var Twelfth_voc_paractical_amrk = parseInt(document.getElementById("Twelfth_voc_paractical_amrk").value) || 0;
  
      // Calculate total marks, cutoff, and PCM average
      var Twelfth_Std_voc_Total_Marks = Twelfth_Std_voc_Language_Mark + Twelfth_Std_voc_English_Mark + Twelfth_Std_voc_chemistry_Mark + Twelfth_Std_voc_Mathematics_or_Physics_Mark + Twelfth_Std_voc_Vocational_Theory_Mark + Twelfth_voc_paractical_amrk;
      var Twelfth_Std_voc_CUT_OFF_Mark = (Twelfth_Std_voc_chemistry_Mark + ((Twelfth_Std_voc_Mathematics_or_Physics_Mark + Twelfth_Std_voc_Vocational_Theory_Mark) / 2));
      var Twelfth_Std_voc_PCM_Average = ((Twelfth_Std_voc_chemistry_Mark + Twelfth_Std_voc_Mathematics_or_Physics_Mark + Twelfth_Std_voc_Vocational_Theory_Mark) / 3);
  
      // Update the corresponding input fields with the calculated values
      document.getElementById("Twelfth_Std_voc_Total_Marks").value = Twelfth_Std_voc_Total_Marks;
      document.getElementById("Twelfth_Std_voc_CUT_OFF_Mark").value = Twelfth_Std_voc_CUT_OFF_Mark.toFixed(2);
      document.getElementById("Twelfth_Std_voc_PCM_Average").value = Twelfth_Std_voc_PCM_Average.toFixed(2);
  }
  














    document.addEventListener("DOMContentLoaded", function () {
      const button1 = document.getElementById("button1");
      const button2 = document.getElementById("button2");
      const div1 = document.getElementById("div1");
      const div2 = document.getElementById("div2");
      const div4 = document.getElementById("div4");
      const div5 = document.getElementById("div5");

      button1.addEventListener("click", function () {
          div1.style.display = "block";
          div2.style.display = "none";
          div4.style.display = "block";
          div5.style.display = "none";
      });

      button2.addEventListener("click", function () {
          div1.style.display = "none";
          div2.style.display = "block";
          div4.style.display = "none";
          div5.style.display = "block";
      });
  });
  function dipcalculation() {
    // SSLC
    var sem1_total_mark = parseInt(document.getElementById("sem1_total_mark").value) || 0;
    var sem2_total_mark = parseInt(document.getElementById("sem2_total_mark").value) || 0;
    var sem3_total_mark = parseInt(document.getElementById("sem3_total_mark").value) || 0;
    var sem4_total_mark = parseInt(document.getElementById("sem4_total_mark").value) || 0;
    var sem5_total_mark = parseInt(document.getElementById("sem5_total_mark").value) || 0;
    var sem6_total_mark = parseInt(document.getElementById("sem6_total_mark").value) || 0;

    // Average
    var sem1_obtain_mark = parseFloat(document.getElementById("sem1_obtain_mark").value) || 0;
    var sem2_obtain_mark = parseFloat(document.getElementById("sem2_obtain_mark").value) || 0;
    var sem3_obtain_mark = parseFloat(document.getElementById("sem3_obtain_mark").value) || 0;
    var sem4_obtain_mark = parseFloat(document.getElementById("sem4_obtain_mark").value) || 0;
    var sem5_obtain_mark = parseFloat(document.getElementById("sem5_obtain_mark").value) || 0;
    var sem6_obtain_mark = parseFloat(document.getElementById("sem6_obtain_mark").value) || 0;

    var diploma_obtain_mark = (sem1_total_mark + sem2_total_mark + sem3_total_mark + sem4_total_mark + sem5_total_mark + sem6_total_mark);
    var diploma_total_mark = (sem1_obtain_mark + sem2_obtain_mark + sem3_obtain_mark + sem4_obtain_mark + sem5_obtain_mark + sem6_obtain_mark);
    var total_percentages = (diploma_total_mark / diploma_obtain_mark)*100;

    document.getElementById("diploma_obtain_mark").value = diploma_obtain_mark;
    document.getElementById("diploma_total_mark").value = diploma_total_mark;
    document.getElementById("total_percentages").value = total_percentages;
}
  
function confirmDelete() {
    // Display a confirmation dialog
    var result = confirm("Are you sure you want to delete?");
    
    // Return true if the user clicks OK, otherwise return false
    return result;
}

function confirmSubmit() {
  // Display a confirmation dialog
  var result = confirm("Are you sure you want to Submit the Form?");
  
  // Return true if the user clicks OK, otherwise return false
  return result;
}

function hideButton() {
  // Check if the page is being shown due to a back-forward navigation
  if (window.performance && window.performance.navigation.type === 2) {
      // If a back-forward navigation, hide the button
      document.getElementById('submitButton').style.display = 'none';
  } else {
      // If not a back-forward navigation, show the button
      document.getElementById('submitButton').style.display = 'block';
  }
}

// Attach the hideButton function to the pageshow event
window.addEventListener('pageshow', hideButton);


$(document).ready(function() {
  // Event listener for changes in any preference select box
  $('.preference-select').change(function() {
      // Get the selected value
      var selectedValue = $(this).val();
      
      // Disable the selected value in all other preference select boxes
      $('.preference-select').not(this).find('option[value="' + selectedValue + '"]').prop('disabled', true);
      
      // Enable all options in the current select box
      $(this).find('option').prop('disabled', false);
  });
});