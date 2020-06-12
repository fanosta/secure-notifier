package com.acn.notifier

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.widget.Toast
import androidx.core.app.ActivityCompat
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.vision.CameraSource
import com.google.android.gms.vision.Detector
import com.google.android.gms.vision.Detector.Detections
import com.google.android.gms.vision.barcode.Barcode
import com.google.android.gms.vision.barcode.BarcodeDetector
import java.io.IOException

class ScannerActivity : Activity() {
  var cameraSurface: SurfaceView? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.scanner)
    cameraSurface = findViewById(R.id.surfaceView)
    createCameraSource()
  }

  private fun createCameraSource() {
    val barcodeDetector = BarcodeDetector.Builder(this).build()
    val cameraSource = CameraSource.Builder(this, barcodeDetector)
      .setAutoFocusEnabled(true)
      .setRequestedPreviewSize(1600, 1024)
      .build()

    if (!barcodeDetector.isOperational) {
      Toast.makeText(
        applicationContext,
        "BarcodeDetector is not Operational",
        Toast.LENGTH_LONG
      ).show()
      finish()
    }

    cameraSurface!!.holder.addCallback(object : SurfaceHolder.Callback {
      override fun surfaceCreated(holder: SurfaceHolder) {
        if (ActivityCompat.checkSelfPermission(
            this@ScannerActivity,
            Manifest.permission.CAMERA
          ) == PackageManager.PERMISSION_DENIED
        ) {
          val requestCode = 100
          ActivityCompat.requestPermissions(
            this@ScannerActivity,
            arrayOf(Manifest.permission.CAMERA),
            requestCode
          )
        }
        try {
          cameraSource.start(cameraSurface!!.holder)
        } catch (e: IOException) {
          e.printStackTrace()
        }
      }

      override fun surfaceChanged(
        holder: SurfaceHolder,
        format: Int,
        width: Int,
        height: Int
      ) {
      }

      override fun surfaceDestroyed(holder: SurfaceHolder) {
        cameraSource.stop()
      }
    })

    barcodeDetector.setProcessor(object : Detector.Processor<Barcode?> {
      override fun release() {}

      override fun receiveDetections(detections: Detections<Barcode?>) {
        val detected_barcode = detections.detectedItems

        if (detected_barcode.size() != 0) {
          val intent = Intent()
          intent.putExtra("received", detected_barcode.valueAt(0))
          setResult(CommonStatusCodes.SUCCESS, intent)
          finish()
        }
      }
    })
  }
}